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
	peerNodes   map[string]*node.PeerNode // Map: Peer IP -> PeerNode client
	selfPrivKey tink.Signer
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewSynchronizer creates a new Synchronizer instance.
func NewSynchronizer(cfg *config.Config, s *store.InMemoryStore, peers map[string]*node.PeerNode) (*Synchronizer, error) {
	if cfg == nil || s == nil || peers == nil {
		return nil, errors.New("config, store, and peer nodes cannot be nil")
	}
	if cfg.PrivKeySigner == nil {
		return nil, errors.New("config is missing private key signer")
	}
	return &Synchronizer{
		cfg:         cfg,
		localStore:  s,
		peerNodes:   peers,
		selfPrivKey: cfg.PrivKeySigner,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start initiates the background polling goroutines for eligible peers.
func (self *Synchronizer) Start(ctx context.Context) {
	slog.Info("Starting synchronizer...")
	for ip, peerNode := range self.peerNodes {
		// Check if this peer is configured for polling
		if peerNode.Config != nil && peerNode.Config.PollInterval != nil && *peerNode.Config.PollInterval > 0 {
			self.wg.Add(1)
			go self.pollPeerLoop(ctx, ip, peerNode, *peerNode.Config.PollInterval)
		} else {
			slog.Info("Peer not configured for polling or interval is zero, skipping", "peer_ip", ip)
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
func (self *Synchronizer) pollPeerLoop(ctx context.Context, peerIP string, peerNode *node.PeerNode, interval time.Duration) {
	defer self.wg.Done()
	slog.Info("Starting polling loop for peer", "peer_ip", peerIP, "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial poll immediately before starting the ticker loop
	self.syncWithPeer(ctx, peerIP, peerNode)

	for {
		select {
		case <-ticker.C:
			self.syncWithPeer(ctx, peerIP, peerNode)
		case <-self.stopChan:
			slog.Info("Stopping polling loop for peer", "peer_ip", peerIP)
			return
		case <-ctx.Done():
			slog.Info("Context cancelled, stopping polling loop for peer", "peer_ip", peerIP, "err", ctx.Err())
			return
		}
	}
}

// syncWithPeer performs a single synchronization cycle with a given peer.
func (self *Synchronizer) syncWithPeer(ctx context.Context, peerIP string, peerNode *node.PeerNode) {
	slog.Debug("Starting sync cycle with peer", "peer_ip", peerIP)

	// 1. Get remote list
	remoteListResp, err := peerNode.CallList(ctx, self.selfPrivKey)
	if err != nil {
		slog.Warn("Failed to get entry list from peer during sync", "peer_ip", peerIP, "err", err)
		return // Skip this cycle if List fails
	}
	slog.Debug("Received entry list from peer", "peer_ip", peerIP, "count", len(remoteListResp.Entries))

	// 2. Get local list (or map for efficient lookup)
	localEntries := self.localStore.GetAllEntries() // Get full entries to compare timestamps
	localEntryMap := make(map[string]*timestamppb.Timestamp, len(localEntries))
	for _, entry := range localEntries {
		localEntryMap[entry.Key] = entry.Timestamp
	}
	slog.Debug("Built local entry map for comparison", "count", len(localEntryMap))

	// 3. Compare and fetch missing/newer entries
	fetchCount := 0
	updateCount := 0
	errorCount := 0
	for _, remoteMeta := range remoteListResp.Entries {
		localTimestamp, exists := localEntryMap[remoteMeta.Key]

		shouldFetch := false
		if !exists {
			slog.Debug("Found new entry on peer", "peer_ip", peerIP, "key", remoteMeta.Key, "timestamp", remoteMeta.Timestamp.AsTime())
			shouldFetch = true
		} else if remoteMeta.Timestamp.AsTime().After(localTimestamp.AsTime()) {
			slog.Debug("Found newer entry on peer", "peer_ip", peerIP, "key", remoteMeta.Key, "remote_ts", remoteMeta.Timestamp.AsTime(), "local_ts", localTimestamp.AsTime())
			shouldFetch = true
		}

		if shouldFetch {
			fetchCount++
			getRequest := &pb.GetRequest{
				Key:       remoteMeta.Key,
				Timestamp: remoteMeta.Timestamp,
			}
			getResponse, err := peerNode.CallGet(ctx, self.selfPrivKey, getRequest)
			if err != nil {
				slog.Warn("Failed to get entry details from peer during sync",
					"peer_ip", peerIP,
					"key", remoteMeta.Key,
					"timestamp", remoteMeta.Timestamp.AsTime(),
					"err", err)
				errorCount++
				continue // Skip this entry if Get fails
			}

			// AddOrUpdateEntry handles signature verification internally
			updated, err := self.localStore.AddOrUpdateEntry(getResponse.Entry)
			if err != nil {
				// This usually means the master signature verification failed
				slog.Warn("Failed to store entry fetched from peer",
					"peer_ip", peerIP,
					"key", remoteMeta.Key,
					"timestamp", remoteMeta.Timestamp.AsTime(),
					"err", err)
				errorCount++
				continue
			}
			if updated {
				updateCount++
				slog.Info("Successfully fetched and stored entry from peer",
					"peer_ip", peerIP,
					"key", remoteMeta.Key,
					"timestamp", remoteMeta.Timestamp.AsTime())
			} else {
				// This could happen if between List and Get, we received an even newer version
				// from another source, or if timestamps were identical.
				slog.Debug("Fetched entry from peer but did not update local store (likely identical or older)",
					"peer_ip", peerIP,
					"key", remoteMeta.Key,
					"timestamp", remoteMeta.Timestamp.AsTime())
			}
		}
	}

	slog.Debug("Finished sync cycle with peer",
		"peer_ip", peerIP,
		"remote_entries", len(remoteListResp.Entries),
		"local_entries", len(localEntryMap),
		"fetched", fetchCount,
		"updated_local_store", updateCount,
		"errors", errorCount)
}
