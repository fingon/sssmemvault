package store

import (
	"errors"
	"fmt"
	"log/slog" // Requires Go 1.21+
	"sync"

	"github.com/fingon/sssmemvault/internal/crypto"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ErrNotFound is returned when a requested entry is not found in the store.
var ErrNotFound = errors.New("entry not found")

// InMemoryStore implements an in-memory storage for secret entries.
// It ensures that only the entry with the latest timestamp for a given key is kept.
type InMemoryStore struct {
	mu           sync.RWMutex
	entries      map[string]*pb.Entry // Key: entry.Key, Value: latest known Entry proto
	masterPubKey tink.Verifier
}

// NewInMemoryStore creates a new in-memory store.
// It requires the master public key verifier to validate entries before storing.
func NewInMemoryStore(masterPubKey tink.Verifier) (*InMemoryStore, error) {
	if masterPubKey == nil {
		return nil, errors.New("master public key verifier cannot be nil")
	}
	return &InMemoryStore{
		entries:      make(map[string]*pb.Entry),
		masterPubKey: masterPubKey,
	}, nil
}

// AddOrUpdateEntry adds a new entry or updates an existing one if the new entry
// has a later timestamp. It verifies the master signature before storing.
func (self *InMemoryStore) AddOrUpdateEntry(entry *pb.Entry) (updated bool, err error) {
	if entry == nil || entry.Timestamp == nil || entry.Key == "" {
		return false, errors.New("invalid entry: cannot be nil, must have timestamp and key")
	}

	// 1. Verify the master signature BEFORE making any changes
	if err := crypto.VerifyEntrySignature(self.masterPubKey, entry); err != nil {
		// Do not store entries with invalid master signatures
		return false, fmt.Errorf("master signature verification failed for incoming entry key %q: %w", entry.Key, err)
	}

	self.mu.Lock()
	defer self.mu.Unlock()

	existingEntry, exists := self.entries[entry.Key]

	// Store if it doesn't exist or if the new entry's timestamp is strictly greater
	if !exists || entry.Timestamp.AsTime().After(existingEntry.Timestamp.AsTime()) {
		// Deep copy the entry before storing to avoid external modifications
		newEntry := proto.Clone(entry).(*pb.Entry)
		self.entries[entry.Key] = newEntry
		slog.Debug("Stored entry", "key", newEntry.Key, "timestamp", newEntry.Timestamp.AsTime(), "existed", exists)
		return true, nil // Indicate that the store was updated
	}

	// If timestamps are equal or the existing is newer, do nothing.
	// Log if timestamps are identical but content differs? Maybe not necessary.
	slog.Debug("Ignored older or identical timestamp entry", "key", entry.Key, "new_ts", entry.Timestamp.AsTime(), "existing_ts", existingEntry.Timestamp.AsTime())
	return false, nil // Indicate that the store was not updated
}

// GetEntry retrieves the specific version of an entry matching the key and timestamp.
// Note: This store only keeps the *latest* version. If a specific older timestamp
// is requested, it won't be found unless it happens to be the latest.
// Consider if the design requires storing all historical versions.
// For now, it only returns the entry if the requested timestamp matches the latest stored one.
func (self *InMemoryStore) GetEntry(key string, timestamp *timestamppb.Timestamp) (*pb.Entry, error) {
	if key == "" || timestamp == nil {
		return nil, errors.New("key and timestamp are required to get a specific entry")
	}

	self.mu.RLock()
	defer self.mu.RUnlock()

	latestEntry, exists := self.entries[key]
	if !exists {
		return nil, fmt.Errorf("%w for key %q", ErrNotFound, key)
	}

	// Check if the requested timestamp matches the latest stored timestamp
	if latestEntry.Timestamp.Seconds == timestamp.Seconds && latestEntry.Timestamp.Nanos == timestamp.Nanos {
		// Return a clone to prevent modification of the stored entry
		return proto.Clone(latestEntry).(*pb.Entry), nil
	}

	// Requested timestamp does not match the latest (and only) stored version
	return nil, fmt.Errorf("entry found for key %q, but timestamp %s does not match stored timestamp %s: %w",
		key, timestamp.AsTime(), latestEntry.Timestamp.AsTime(), ErrNotFound)
}

// GetLatestEntry retrieves the latest known version of an entry for a given key.
func (self *InMemoryStore) GetLatestEntry(key string) (*pb.Entry, error) {
	if key == "" {
		return nil, errors.New("key is required to get the latest entry")
	}

	self.mu.RLock()
	defer self.mu.RUnlock()

	latestEntry, exists := self.entries[key]
	if !exists {
		return nil, fmt.Errorf("%w for key %q", ErrNotFound, key)
	}

	// Return a clone to prevent modification of the stored entry
	return proto.Clone(latestEntry).(*pb.Entry), nil
}

// ListEntries returns metadata (timestamp and key) for all stored entries.
func (self *InMemoryStore) ListEntries() []*pb.EntryMetadata {
	self.mu.RLock()
	defer self.mu.RUnlock()

	metadataList := make([]*pb.EntryMetadata, 0, len(self.entries))
	for _, entry := range self.entries {
		metadataList = append(metadataList, &pb.EntryMetadata{
			Timestamp: entry.Timestamp,
			Key:       entry.Key,
		})
	}
	return metadataList
}

// GetAllEntries returns a copy of all full entries currently in the store.
// Use with caution, potentially large data transfer. Primarily for debugging or specific internal use.
func (self *InMemoryStore) GetAllEntries() []*pb.Entry {
	self.mu.RLock()
	defer self.mu.RUnlock()

	entryList := make([]*pb.Entry, 0, len(self.entries))
	for _, entry := range self.entries {
		// Return clones to prevent modification of the stored entries
		entryList = append(entryList, proto.Clone(entry).(*pb.Entry))
	}
	return entryList
}
