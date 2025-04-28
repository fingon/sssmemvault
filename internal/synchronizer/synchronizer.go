package synchronizer

import (
	"context"
	"errors"
	"log/slog" // Requires Go 1.21+
	"sync"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/node"
	"github.com/fingon/sssmemvault/internal/store"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Synchronizer handles polling peer nodes and updating the local store.
type Synchronizer struct {
	cfg         *config.Config
	localStore  *store.InMemoryStore
	peerNodes   map[string]*node.PeerNode // Map: Peer Name -> PeerNode client
	selfName    string                    // Name of the node running this synchronizer
	selfPrivKey tink.Signer
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewSynchronizer creates a new Synchronizer instance.
func NewSynchronizer(cfg *config.Config, s *store.InMemoryStore, peers map[string]*node.PeerNode, selfName string) (*Synchronizer, error) {
	if cfg == nil || s == nil || peers == nil {
		return nil, errors.New("config, store, and peer nodes cannot be nil")
	}
	if cfg.PrivKeySigner == nil {
		return nil, errors.New("config is missing private key signer")
	}
	if selfName == "" {
		return nil, errors.New("selfName cannot be empty")
	}
	return &Synchronizer{
		cfg:         cfg,
		localStore:  s,
		peerNodes:   peers,
		selfName:    selfName,
		selfPrivKey: cfg.PrivKeySigner,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start initiates the background polling goroutines for eligible peers.
func (self *Synchronizer) Start(ctx context.Context) {
	slog.Info("Starting synchronizer...", "self_name", self.selfName)
	for name, peerNode := range self.peerNodes {
		// Check if this peer is configured for polling
		if peerNode.Config != nil && peerNode.Config.PollInterval != nil && *peerNode.Config.PollInterval > 0 {
			self.wg.Add(1)
			go self.pollPeerLoop(ctx, name, peerNode, *peerNode.Config.PollInterval)
		} else {
			slog.Info("Peer not configured for polling or interval is zero, skipping", "peer_name", name)
		}
	}
	slog.Info("Synchronizer started")
}

// Stop signals all polling goroutines to stop and waits for them to finish.
func (self *Synchronizer) Stop() {
	slog.Info("Stopping synchronizer...")
	close(self.stopChan) // Signal all goroutines to exit
	self.wg.Wait()       // Wait for all goroutines to finish
	slog.Info("Synchronizer stopped")
}

// pollPeerLoop is the main loop for polling a single peer.
func (self *Synchronizer) pollPeerLoop(ctx context.Context, peerName string, peerNode *node.PeerNode, interval time.Duration) {
	defer self.wg.Done()
	slog.Info("Starting polling loop for peer", "peer_name", peerName, "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial poll immediately before starting the ticker loop
	self.syncWithPeer(ctx, peerName, peerNode)

	for {
		select {
		case <-ticker.C:
			self.syncWithPeer(ctx, peerName, peerNode)
		case <-self.stopChan:
			slog.Info("Stopping polling loop for peer", "peer_name", peerName)
			return
		case <-ctx.Done():
			slog.Info("Context cancelled, stopping polling loop for peer", "peer_name", peerName, "err", ctx.Err())
			return
		}
	}
}

// getRemoteEntries fetches the list of entry metadata from a peer.
func (self *Synchronizer) getRemoteEntries(ctx context.Context, peerName string, peerNode *node.PeerNode) ([]*pb.EntryMetadata, error) {
	remoteListResp, err := peerNode.CallList(ctx, self.selfName, self.selfPrivKey)
	if err != nil {
		slog.Warn("Failed to get entry list from peer during sync", "peer_name", peerName, "err", err)
		return nil, err // Return error to caller
	}
	slog.Debug("Received entry list from peer", "peer_name", peerName, "count", len(remoteListResp.Entries))
	return remoteListResp.Entries, nil
}

// getLocalEntryMap builds a map of local entry keys to their timestamps.
func (self *Synchronizer) getLocalEntryMap() map[string]*timestamppb.Timestamp {
	localEntries := self.localStore.GetAllEntries() // Get full entries to compare timestamps
	localEntryMap := make(map[string]*timestamppb.Timestamp, len(localEntries))
	for _, entry := range localEntries {
		localEntryMap[entry.Key] = entry.Timestamp
	}
	slog.Debug("Built local entry map for comparison", "count", len(localEntryMap))
	return localEntryMap
}

// shouldFetchEntry determines if an entry from a peer needs to be fetched.
func shouldFetchEntry(remoteMeta *pb.EntryMetadata, localEntryMap map[string]*timestamppb.Timestamp, peerName string) bool {
	localTimestamp, exists := localEntryMap[remoteMeta.Key]
	if !exists {
		slog.Debug("Found new entry on peer", "peer_name", peerName, "key", remoteMeta.Key, "timestamp", remoteMeta.Timestamp.AsTime())
		return true
	}
	if remoteMeta.Timestamp.AsTime().After(localTimestamp.AsTime()) {
		slog.Debug("Found newer entry on peer", "peer_name", peerName, "key", remoteMeta.Key, "remote_ts", remoteMeta.Timestamp.AsTime(), "local_ts", localTimestamp.AsTime())
		return true
	}
	return false
}

// fetchAndUpdateEntry fetches a specific entry from a peer and updates the local store.
func (self *Synchronizer) fetchAndUpdateEntry(ctx context.Context, peerName string, peerNode *node.PeerNode, remoteMeta *pb.EntryMetadata) (updated bool, err error) {
	getRequest := &pb.GetRequest{
		Key:       remoteMeta.Key,
		Timestamp: remoteMeta.Timestamp,
	}
	// Authenticate Get call using selfName
	getResponse, err := peerNode.CallGet(ctx, self.selfName, self.selfPrivKey, getRequest)
	if err != nil {
		slog.Warn("Failed to get entry details from peer during sync",
			"peer_name", peerName,
			"key", remoteMeta.Key,
			"timestamp", remoteMeta.Timestamp.AsTime(),
			"err", err)
		return false, err // Return error
	}

	// AddOrUpdateEntry handles signature verification internally
	updated, err = self.localStore.AddOrUpdateEntry(getResponse.Entry)
	if err != nil {
		// This usually means the master signature verification failed
		slog.Warn("Failed to store entry fetched from peer",
			"peer_name", peerName,
			"key", remoteMeta.Key,
			"timestamp", remoteMeta.Timestamp.AsTime(),
			"err", err)
		return false, err // Return error
	}

	if updated {
		slog.Info("Successfully fetched and stored entry from peer",
			"peer_name", peerName,
			"key", remoteMeta.Key,
			"timestamp", remoteMeta.Timestamp.AsTime())
	} else {
		slog.Debug("Fetched entry from peer but did not update local store (likely identical or older)",
			"peer_name", peerName,
			"key", remoteMeta.Key,
			"timestamp", remoteMeta.Timestamp.AsTime())
	}
	return updated, nil
}

// syncWithPeer performs a single synchronization cycle with a given peer.
func (self *Synchronizer) syncWithPeer(ctx context.Context, peerName string, peerNode *node.PeerNode) {
	slog.Debug("Starting sync cycle with peer", "peer_name", peerName)

	// 1. Get remote list
	remoteEntries, err := self.getRemoteEntries(ctx, peerName, peerNode)
	if err != nil {
		return // Error already logged
	}

	// 2. Get local map
	localEntryMap := self.getLocalEntryMap()

	// 3. Compare and fetch missing/newer entries
	fetchCount := 0
	updateCount := 0
	errorCount := 0
	for _, remoteMeta := range remoteEntries {
		if shouldFetchEntry(remoteMeta, localEntryMap, peerName) {
			fetchCount++
			updated, err := self.fetchAndUpdateEntry(ctx, peerName, peerNode, remoteMeta)
			if err != nil {
				errorCount++
				// Error already logged in fetchAndUpdateEntry
				continue
			}
			if updated {
				updateCount++
			}
		}
	}

	slog.Debug("Finished sync cycle with peer",
		"peer_name", peerName,
		"remote_entries", len(remoteEntries),
		"local_entries", len(localEntryMap),
		"fetched", fetchCount,
		"updated_local_store", updateCount,
		"errors", errorCount)
}
