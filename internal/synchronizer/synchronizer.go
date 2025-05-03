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
	cfg         *config.Config // Holds all peer configs
	localStore  *store.InMemoryStore
	selfName    string // Name of the node running this synchronizer
	selfPrivKey tink.Signer
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewSynchronizer creates a new Synchronizer instance.
func NewSynchronizer(cfg *config.Config, s *store.InMemoryStore, selfName string) (*Synchronizer, error) {
	if cfg == nil || s == nil {
		return nil, errors.New("config and store cannot be nil")
	}
	if cfg.PrivKeySigner == nil {
		return nil, errors.New("config is missing private key signer") // Signer needed for authenticated calls
	}
	if selfName == "" {
		return nil, errors.New("selfName cannot be empty")
	}
	return &Synchronizer{
		cfg:         cfg,
		localStore:  s,
		selfName:    selfName,
		selfPrivKey: cfg.PrivKeySigner,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start initiates the background polling goroutines for eligible peers defined in the config.
func (self *Synchronizer) Start(ctx context.Context) {
	slog.Info("Starting synchronizer...", "self_name", self.selfName)
	// Iterate through peers defined in the configuration
	for name, peerCfg := range self.cfg.LoadedPeers {
		switch {
		case name == self.selfName:
			slog.Debug("Skipping polling loop for self", "peer_name", name)
		case peerCfg == nil || peerCfg.PollInterval == nil || *peerCfg.PollInterval <= 0:
			slog.Info("Peer not configured for polling or interval is zero, skipping", "peer_name", name)
		default:
			// Peer is not self and is configured for polling
			self.wg.Add(1)
			// Pass peer name and config to the loop
			go self.pollPeerLoop(ctx, name, peerCfg, *peerCfg.PollInterval)
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

// pollPeerLoop is the main loop for polling a single peer, using its configuration.
func (self *Synchronizer) pollPeerLoop(ctx context.Context, peerName string, peerCfg *config.PeerConfig, interval time.Duration) {
	defer self.wg.Done()
	slog.Info("Starting polling loop for peer", "peer_name", peerName, "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial poll immediately before starting the ticker loop
	self.syncWithPeer(ctx, peerName, peerCfg)

	for {
		select {
		case <-ticker.C:
			self.syncWithPeer(ctx, peerName, peerCfg)
		case <-self.stopChan:
			slog.Info("Stopping polling loop for peer", "peer_name", peerName)
			return
		case <-ctx.Done():
			slog.Info("Context cancelled, stopping polling loop for peer", "peer_name", peerName, "err", ctx.Err())
			return
		}
	}
}

// getRemoteEntries fetches the list of entry metadata from a connected peer node.
func (self *Synchronizer) getRemoteEntries(ctx context.Context, peerName string, peerNode *node.PeerNode) ([]*pb.EntryMetadata, error) {
	// Use a shorter timeout for the specific RPC call
	callCtx, callCancel := context.WithTimeout(ctx, 15*time.Second)
	defer callCancel()

	remoteListResp, err := peerNode.CallList(callCtx, self.selfName, self.selfPrivKey)
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

// fetchAndUpdateEntry fetches a specific entry from a connected peer node and updates the local store.
func (self *Synchronizer) fetchAndUpdateEntry(ctx context.Context, peerName string, peerNode *node.PeerNode, remoteMeta *pb.EntryMetadata) (updated bool, err error) {
	getRequest := &pb.GetRequest{
		Key:       remoteMeta.Key,
		Timestamp: remoteMeta.Timestamp,
	}

	// Use a shorter timeout for the specific RPC call
	callCtx, callCancel := context.WithTimeout(ctx, 15*time.Second)
	defer callCancel()

	// Authenticate Get call using selfName
	getResponse, err := peerNode.CallGet(callCtx, self.selfName, self.selfPrivKey, getRequest)
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

// syncWithPeer performs a single synchronization cycle with a given peer using its config.
// It connects, syncs, and disconnects.
func (self *Synchronizer) syncWithPeer(ctx context.Context, peerName string, peerCfg *config.PeerConfig) {
	slog.Debug("Starting sync cycle with peer", "peer_name", peerName, "endpoint", peerCfg.Endpoint)

	// Use a timeout for the connection attempt for this cycle
	connectCtx, connectCancel := context.WithTimeout(ctx, 30*time.Second)
	defer connectCancel()

	// 1. Connect to peer for this cycle
	peerNode, err := node.ConnectToPeer(connectCtx, peerName, peerCfg)
	if err != nil {
		slog.Warn("Failed to connect to peer for sync cycle", "peer_name", peerName, "endpoint", peerCfg.Endpoint, "err", err)
		return // Cannot sync if connection fails
	}
	defer func() {
		if err := peerNode.Close(); err != nil {
			slog.Warn("Error closing connection after sync cycle", "peer_name", peerName, "err", err)
		}
	}()

	// 2. Get remote list using the established connection
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
