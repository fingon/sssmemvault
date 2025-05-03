package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/fingon/sssmemvault/internal/node"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config holds the specific configuration needed for the push subcommand.
type Config struct {
	MasterPrivateKeyPath string   `kong:"name='master-private-key',required,help='Path to the master private key JSON file (signing only).'"`
	Readers              []string `kong:"name='reader',required,help='Name of a node allowed to read the secret. Repeat for each reader.'"`
	Key                  string   `kong:"name='key',required,help='The key name for the secret.'"`
	Secret               string   `kong:"name='secret',required,help='The secret value to store.'"`
	Threshold            int      `kong:"name='threshold',short='t',required,help='Shamir threshold (number of fragments needed to reconstruct).'"`
	// Parts is now calculated based on sum of fragments_per_owner in config for owner peers.
	Targets    []string `kong:"name='target',optional,help='Endpoint address (host:port) of a target node to push to. Repeat for each target. Can be sourced from --config.'"`
	ConfigPath string   `kong:"name='config',required,help='Path to a configuration file to load parameters from (peers, targets).'"`
	// LogLevel is handled globally
}

// loadConfigAndDeriveTargets loads the configuration file and derives targets if needed.
// Owners are now implicitly defined by the peers in the config file.
func loadConfigAndDeriveTargets(pushCfg *Config) (*config.Config, error) {
	if pushCfg.ConfigPath == "" {
		// Config path is now required by kong
		return nil, errors.New("configuration file path is required")
	}

	slog.Info("Loading configuration file", "path", pushCfg.ConfigPath)
	// Load config, ignoring own private key errors as push uses the master key
	appCfg, err := config.LoadConfigIgnoreOwnKey(pushCfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file %q: %w", pushCfg.ConfigPath, err)
	}
	slog.Info("Configuration loaded successfully", "path", pushCfg.ConfigPath)

	// Populate targets from config if not provided via flags
	if len(pushCfg.Targets) == 0 {
		slog.Debug("Populating targets from config file")
		if appCfg.LoadedPeers == nil || len(appCfg.LoadedPeers) == 0 {
			return nil, errors.New("config file specified but contains no peers to use as targets")
		}
		// Endpoints are validated during config.LoadConfig, so we assume they exist here.
		for name, peerCfg := range appCfg.LoadedPeers {
			if peerCfg.Endpoint != "" { // Only add peers with endpoints as targets
				pushCfg.Targets = append(pushCfg.Targets, peerCfg.Endpoint)
			} else {
				slog.Debug("Skipping peer as target (no endpoint defined)", "peer_name", name)
			}
		}
		slog.Info("Using targets derived from config file", "count", len(pushCfg.Targets))
	}
	return appCfg, nil
}

// prepareFragments splits the secret and encrypts fragments for each owner peer defined in the config,
// respecting the FragmentsPerOwner setting for each peer.
func prepareFragments(secret string, threshold int, appCfg *config.Config) (map[string]*pb.FragmentList, error) {
	// Identify owner peers (those with loaded encrypters AND endpoints in the config)
	// and calculate total parts needed.
	ownerPeers := make(map[string]*config.PeerConfig)
	totalParts := 0
	for name, peerCfg := range appCfg.LoadedPeers {
		// An owner must have an encrypter AND an endpoint to receive the push.
		if peerCfg.PubKeyEncrypter != nil && peerCfg.Endpoint != "" {
			ownerPeers[name] = peerCfg
			totalParts += peerCfg.FragmentsPerOwner
			slog.Debug("Identified owner peer", "name", name, "fragments_per_owner", peerCfg.FragmentsPerOwner)
		} else {
			slog.Debug("Peer does not qualify as an owner (missing encrypter or endpoint)", "peer_name", name, "has_encrypter", peerCfg.PubKeyEncrypter != nil, "has_endpoint", peerCfg.Endpoint != "")
		}
	}
	numOwners := len(ownerPeers)
	if numOwners == 0 {
		return nil, errors.New("no owner peers found in configuration (peers with public keys and endpoints)")
	}
	if totalParts == 0 {
		// Should not happen if numOwners > 0 and default is 1, but check defensively
		return nil, errors.New("calculated total parts is zero, check fragments_per_owner in config")
	}
	if threshold > totalParts {
		return nil, fmt.Errorf("threshold (%d) cannot be greater than the total number of fragments (%d) calculated from owner peers", threshold, totalParts)
	}
	slog.Info("Identified owner peers from config", "count", numOwners, "total_fragments", totalParts, "names", ownerPeers) // Consider logging names if not too many

	slog.Debug("Splitting secret", "total_parts", totalParts, "threshold", threshold)
	fragments, err := crypto.SplitSecret([]byte(secret), totalParts, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}
	slog.Info("Secret split into fragments", "count", len(fragments))

	// Encrypt Fragments and distribute according to FragmentsPerOwner
	ownerEncryptedFragments := make(map[string]*pb.FragmentList)
	fragmentIndex := 0
	for ownerName, ownerCfg := range ownerPeers {
		if ownerCfg.PubKeyEncrypter == nil {
			// Should have been filtered already, but double-check
			return nil, fmt.Errorf("internal error: missing encrypter for owner %q", ownerName)
		}
		encrypter := ownerCfg.PubKeyEncrypter
		numFragsForOwner := ownerCfg.FragmentsPerOwner

		slog.Debug("Assigning fragments to owner", "owner_name", ownerName, "count", numFragsForOwner)
		ownerList := &pb.FragmentList{Fragments: make([][]byte, 0, numFragsForOwner)}

		for range numFragsForOwner {
			if fragmentIndex >= len(fragments) {
				return nil, fmt.Errorf("internal error: not enough fragments generated for distribution (needed %d, generated %d)", totalParts, len(fragments))
			}
			fragment := fragments[fragmentIndex]
			currentFragIndex := fragmentIndex // Capture for logging

			slog.Debug("Encrypting fragment for owner", "fragment_index", currentFragIndex, "owner_name", ownerName)
			encrypted, err := crypto.EncryptFragment(encrypter, fragment)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt fragment %d for owner %q (%s): %w",
					currentFragIndex, ownerName, ownerCfg.PublicKeyPath, err)
			}
			ownerList.Fragments = append(ownerList.Fragments, encrypted)
			fragmentIndex++
		}
		ownerEncryptedFragments[ownerName] = ownerList
		slog.Debug("Finished assigning fragments to owner", "owner_name", ownerName, "assigned_count", len(ownerList.Fragments))
	}

	// Sanity check: ensure all fragments were assigned
	if fragmentIndex != len(fragments) {
		return nil, fmt.Errorf("internal error: fragment count mismatch after distribution (assigned %d, total %d)", fragmentIndex, len(fragments))
	}
	slog.Info("Finished encrypting and distributing fragments")
	return ownerEncryptedFragments, nil
}

// buildAndSignEntry constructs the protobuf Entry and signs it.
func buildAndSignEntry(pushCfg *Config, ownerEncryptedFragments map[string]*pb.FragmentList, masterSigner tink.Signer) (*pb.Entry, error) {
	entry := &pb.Entry{
		Timestamp:      timestamppb.Now(),
		Key:            pushCfg.Key,
		Readers:        pushCfg.Readers, // Already a slice of strings
		OwnerFragments: ownerEncryptedFragments,
		Threshold:      int32(pushCfg.Threshold),
		// Signature will be added next
	}
	slog.Debug("Constructed entry structure", "key", entry.Key, "timestamp", entry.Timestamp.AsTime(), "threshold", entry.Threshold)

	// Sign Entry
	slog.Debug("Signing entry with master key")
	err := crypto.SignEntry(masterSigner, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}
	slog.Info("Entry signed successfully")
	return entry, nil
}

// pushEntryToTargets pushes the signed entry to all target nodes concurrently.
func pushEntryToTargets(targets []string, entry *pb.Entry) (successCount, errorCount int) {
	pushRequest := &pb.PushRequest{Entry: entry}
	var wg sync.WaitGroup
	var mu sync.Mutex // To protect counters

	// Use a shared context for all push operations
	pushCtx, pushCancel := context.WithTimeout(context.Background(), 60*time.Second) // Overall timeout for pushing
	defer pushCancel()

	for _, target := range targets {
		wg.Add(1)
		go func(targetEndpoint string) {
			defer wg.Done()
			slog.Info("Connecting to target node", "endpoint", targetEndpoint)
			conn, err := node.DialPeer(pushCtx, targetEndpoint) // Use a simplified dial function
			if err != nil {
				slog.Error("Failed to connect to target", "endpoint", targetEndpoint, "err", err)
				mu.Lock()
				errorCount++
				mu.Unlock()
				return
			}
			defer func() {
				err := conn.Close()
				if err != nil {
					slog.Warn("Error closing connection to target", "endpoint", targetEndpoint, "err", err)
				}
			}()

			client := pb.NewSssMemVaultClient(conn)
			// Use a derived context with a shorter timeout for the actual RPC call
			callCtx, callCancel := context.WithTimeout(pushCtx, 30*time.Second)
			defer callCancel()

			slog.Info("Pushing entry to target", "endpoint", targetEndpoint, "key", entry.Key)
			_, err = client.Push(callCtx, pushRequest) // Use callCtx

			mu.Lock()
			if err != nil {
				slog.Error("Failed to push entry to target", "endpoint", targetEndpoint, "key", entry.Key, "err", err)
				errorCount++
			} else {
				slog.Info("Successfully pushed entry to target", "endpoint", targetEndpoint, "key", entry.Key)
				successCount++
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	slog.Info("Push operation complete", "successful_targets", successCount, "failed_targets", errorCount)
	return successCount, errorCount
}

// Run executes the push operation.
func Run(pushCfg *Config) int {
	slog.Info("Starting push operation...")

	// --- Load Config and derive targets ---
	appCfg, err := loadConfigAndDeriveTargets(pushCfg)
	if err != nil {
		slog.Error("Failed to load or process configuration", "err", err)
		return 1
	}

	// --- Validate Inputs (Post-Config Load/Derivation) ---
	// Threshold validation remains (checked against calculated total parts in prepareFragments)
	if pushCfg.Threshold <= 0 {
		slog.Error("Threshold must be positive", "threshold", pushCfg.Threshold)
		return 1
	}
	if len(pushCfg.Readers) == 0 {
		slog.Error("At least one reader must be specified")
		return 1
	}
	if len(pushCfg.Targets) == 0 {
		slog.Error("No targets specified. Provide via --target flags or derive from --config file.")
		return 1
	}

	// --- Load Master Signing Key ---
	slog.Debug("Loading master private key (signer)", "path", pushCfg.MasterPrivateKeyPath)
	// Use the generic LoadSigner function
	masterSigner, err := crypto.LoadSigner(pushCfg.MasterPrivateKeyPath)
	if err != nil {
		slog.Error("Failed to load master private key (signer)", "path", pushCfg.MasterPrivateKeyPath, "err", err)
		return 1
	}
	slog.Info("Loaded master private key (signer) successfully")

	// --- Split Secret and Encrypt Fragments ---
	// Owners, their keys, and fragment counts are derived directly from appCfg
	ownerEncryptedFragments, err := prepareFragments(pushCfg.Secret, pushCfg.Threshold, appCfg)
	if err != nil {
		slog.Error("Failed to prepare fragments", "err", err)
		return 1
	}

	// --- Construct and Sign Entry ---
	entry, err := buildAndSignEntry(pushCfg, ownerEncryptedFragments, masterSigner)
	if err != nil {
		slog.Error("Failed to build or sign entry", "err", err)
		return 1
	}

	// --- Push to Targets ---
	_, errorCount := pushEntryToTargets(pushCfg.Targets, entry)

	if errorCount > 0 {
		return 1 // Exit with error if any push failed
	}
	return 0 // Exit successfully
}
