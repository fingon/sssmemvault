package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/fingon/sssmemvault/internal/node"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// OwnerInfo holds the Name, hybrid public key path, and desired fragment count for an owner node.
type OwnerInfo struct {
	Name            string
	HybridPublicKey string // Path to the public key used for encrypting fragments
	Count           int    // Number of fragments this owner should receive
}

// Config holds the specific configuration needed for the push subcommand.
type Config struct {
	MasterSigningPrivateKey string   `kong:"name='master-signing-key',required,help='Path to the master private key JSON file (for signing entries).'"`
	Owners                  []string `kong:"name='owner',optional,help='Owner node info as Name=HybridPublicKeyPath:Count (e.g., node1=owner1_hybrid_pub.json:2). Repeat for each owner. Total count must match --parts. Can be sourced from --config (count defaults to 1 if format is Name=Path).'"`
	Readers                 []string `kong:"name='reader',required,help='Name of a node allowed to read the secret. Repeat for each reader.'"`
	Key                     string   `kong:"name='key',required,help='The key name for the secret.'"`
	Secret                  string   `kong:"name='secret',required,help='The secret value to store.'"`
	Threshold               int      `kong:"name='threshold',short='t',required,help='Shamir threshold (number of fragments needed to reconstruct).'"`
	Parts                   int      `kong:"name='parts',short='p',required,help='Total number of Shamir fragments to create (must match number of owners).'"`
	Targets                 []string `kong:"name='target',optional,help='Endpoint address (host:port) of a target node to push to. Repeat for each target. Can be sourced from --config.'"`
	ConfigPath              string   `kong:"name='config',optional,help='Path to a configuration file to load parameters from (owners, targets).'"`
	// LogLevel is handled globally
}

// parseOwner parses the Name=HybridPublicKeyPath[:Count] string. Count defaults to 1 if omitted.
func parseOwner(ownerStr string) (*OwnerInfo, error) {
	parts := strings.SplitN(ownerStr, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid owner format, expected Name=HybridPublicKeyPath[:Count], got %q", ownerStr)
	}
	name := parts[0]
	pathAndCount := parts[1]

	var path string
	var countStr string
	count := 1 // Default count

	// Check if count is provided
	countParts := strings.SplitN(pathAndCount, ":", 2)
	if len(countParts) == 2 {
		path = countParts[0]
		countStr = countParts[1]
		parsedCount, err := strconv.Atoi(countStr)
		if err != nil || parsedCount <= 0 {
			return nil, fmt.Errorf("invalid count %q for owner %q: must be a positive integer", countStr, name)
		}
		count = parsedCount
	} else {
		// No count provided, use default
		path = pathAndCount
	}

	if path == "" {
		return nil, fmt.Errorf("invalid owner format, missing public key path for Name %q in %q", name, ownerStr)
	}

	// Basic name validation could be added here if needed (e.g., non-empty)
	return &OwnerInfo{Name: name, HybridPublicKey: path, Count: count}, nil
}

// loadConfigAndDeriveParams loads the configuration file if specified and updates
// the push Config struct with owners and targets derived from the config if they weren't
// provided via command-line flags. It returns the loaded app config or nil.
func loadConfigAndDeriveParams(pushCfg *Config) (*config.Config, error) {
	if pushCfg.ConfigPath == "" {
		return nil, nil // No config file specified, nothing to do
	}

	slog.Info("Loading configuration file", "path", pushCfg.ConfigPath)
	appCfg, err := config.LoadConfig(pushCfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file %q: %w", pushCfg.ConfigPath, err)
	}
	slog.Info("Configuration loaded successfully", "path", pushCfg.ConfigPath)

	// Populate owners from config if not provided via flags
	if len(pushCfg.Owners) == 0 {
		slog.Debug("Populating owners from config file")
		if appCfg.Peers == nil || len(appCfg.Peers) == 0 {
			return nil, errors.New("config file specified but contains no peers to use as owners")
		}
		for name, peerCfg := range appCfg.Peers { // Iterate over name-keyed map
			if peerCfg.HybridPublicKey == "" {
				// This check might be redundant if LoadConfig enforces it, but good defense.
				return nil, fmt.Errorf("peer %q in config file is missing hybrid_public_key path", name)
			}
			// Use the HybridPublicKey path for the owner string, format: Name=Path
			// Count defaults to 1 when deriving from config this way.
			pushCfg.Owners = append(pushCfg.Owners, fmt.Sprintf("%s=%s", name, peerCfg.HybridPublicKey))
		}
		slog.Info("Using owners derived from config file", "count", len(pushCfg.Owners))
	}

	// Populate targets from config if not provided via flags
	if len(pushCfg.Targets) == 0 {
		slog.Debug("Populating targets from config file")
		if appCfg.Peers == nil || len(appCfg.Peers) == 0 {
			return nil, errors.New("config file specified but contains no peers to use as targets")
		}
		// Endpoints are validated during config.LoadConfig, so we assume they exist here.
		for _, peerCfg := range appCfg.Peers { // Iterate over original Peers map
			pushCfg.Targets = append(pushCfg.Targets, peerCfg.Endpoint)
		}
		slog.Info("Using targets derived from config file", "count", len(pushCfg.Targets))
	}
	return appCfg, nil
}

// Run executes the push operation.
func Run(pushCfg *Config) int {
	slog.Info("Starting push operation...")

	// --- Load Config if specified and derive parameters ---
	_, err := loadConfigAndDeriveParams(pushCfg)
	if err != nil {
		slog.Error("Failed to load or process configuration", "err", err)
		return 1
	}

	// --- Validate Inputs (Post-Config Load/Derivation) ---
	if len(pushCfg.Owners) == 0 {
		slog.Error("No owners specified. Provide via --owner flags or --config file.")
		return 1
	}
	// Allow parts != owners for round-robin distribution
	// if pushCfg.Parts != len(pushCfg.Owners) {
	// 	slog.Error("Number of owners must match the number of parts", "parts", pushCfg.Parts, "owners", len(pushCfg.Owners))
	// 	return 1
	// }
	if pushCfg.Parts <= 0 {
		slog.Error("Number of parts must be positive", "parts", pushCfg.Parts)
		return 1
	}
	if pushCfg.Threshold > pushCfg.Parts {
		slog.Error("Threshold cannot be greater than the number of parts", "threshold", pushCfg.Threshold, "parts", pushCfg.Parts)
		return 1
	}
	if pushCfg.Threshold <= 0 {
		slog.Error("Threshold must be positive", "threshold", pushCfg.Threshold)
		return 1
	}
	if len(pushCfg.Readers) == 0 {
		slog.Error("At least one reader IP must be specified")
		return 1
	}
	if len(pushCfg.Targets) == 0 {
		slog.Error("No targets specified. Provide via --target flags or --config file.")
		return 1
	}

	// --- Load Master Signing Key ---
	slog.Debug("Loading master signing private key", "path", pushCfg.MasterSigningPrivateKey)
	masterSigner, err := crypto.LoadMasterPrivateKeySigner(pushCfg.MasterSigningPrivateKey)
	if err != nil {
		slog.Error("Failed to load master signing private key", "path", pushCfg.MasterSigningPrivateKey, "err", err)
		return 1
	}
	slog.Info("Loaded master signing private key successfully")

	// --- Parse Owner Info and Load Keys ---
	ownerHybridEncrypters := make(map[string]tink.HybridEncrypt) // Map: Name -> Encrypter
	ownerInfos := make([]*OwnerInfo, 0, len(pushCfg.Owners))
	ownerNameSet := make(map[string]struct{}) // To check for duplicate names
	totalFragmentCountSpecified := 0
	for _, ownerStr := range pushCfg.Owners {
		ownerInfo, err := parseOwner(ownerStr)
		if err != nil {
			slog.Error("Failed to parse owner info", "input", ownerStr, "err", err)
			return 1
		}
		if _, exists := ownerNameSet[ownerInfo.Name]; exists {
			slog.Error("Duplicate owner Name specified", "name", ownerInfo.Name)
			return 1
		}
		ownerNameSet[ownerInfo.Name] = struct{}{}
		ownerInfos = append(ownerInfos, ownerInfo) // Keep order for fragment assignment

		// Load the hybrid public key using the path from the owner string
		slog.Debug("Loading owner hybrid public key", "name", ownerInfo.Name, "path", ownerInfo.HybridPublicKey)
		encrypter, err := crypto.LoadOwnerPublicKeyEncrypter(ownerInfo.HybridPublicKey)
		if err != nil {
			slog.Error("Failed to load owner hybrid public key", "name", ownerInfo.Name, "path", ownerInfo.HybridPublicKey, "err", err)
			return 1
		}
		ownerHybridEncrypters[ownerInfo.Name] = encrypter
		totalFragmentCountSpecified += ownerInfo.Count
		slog.Info("Loaded owner hybrid public key", "name", ownerInfo.Name, "count", ownerInfo.Count)
	}

	// --- Validate Total Fragment Count ---
	if totalFragmentCountSpecified != pushCfg.Parts {
		slog.Error("Total fragment count specified by owners does not match --parts",
			"total_specified", totalFragmentCountSpecified,
			"parts_flag", pushCfg.Parts)
		return 1
	}

	// --- Split Secret ---
	slog.Debug("Splitting secret", "parts", pushCfg.Parts, "threshold", pushCfg.Threshold)
	fragments, err := crypto.SplitSecret([]byte(pushCfg.Secret), pushCfg.Parts, pushCfg.Threshold) // Threshold is int from flags
	if err != nil {
		slog.Error("Failed to split secret", "err", err)
		return 1
	}
	slog.Info("Secret split into fragments", "count", len(fragments))

	// --- Encrypt Fragments ---
	// Map: Owner Name -> List of Encrypted Fragments
	ownerEncryptedFragments := make(map[string]*pb.FragmentList)
	numOwners := len(ownerInfos)
	if numOwners == 0 {
		// Should have been caught by validation, but double-check
		slog.Error("Internal error: No owner info available for fragment encryption")
		return 1
	}
	if len(fragments) != pushCfg.Parts {
		// This should not happen if SplitSecret worked correctly
		slog.Error("Internal error: fragment count mismatch", "fragments", len(fragments), "expected_parts", pushCfg.Parts)
		return 1
	}

	slog.Info("Encrypting and distributing fragments according to owner counts", "fragment_count", len(fragments), "owner_count", numOwners)
	fragmentIndex := 0
	for _, ownerInfo := range ownerInfos {
		encrypter := ownerHybridEncrypters[ownerInfo.Name]
		slog.Debug("Assigning fragments to owner", "owner_name", ownerInfo.Name, "count", ownerInfo.Count)

		// Initialize the list for this owner
		ownerEncryptedFragments[ownerInfo.Name] = &pb.FragmentList{Fragments: make([][]byte, 0, ownerInfo.Count)}

		for range ownerInfo.Count {
			if fragmentIndex >= len(fragments) {
				// Should have been caught by validation, but safeguard
				slog.Error("Internal error: Not enough fragments generated for distribution", "needed", totalFragmentCountSpecified, "generated", len(fragments))
				return 1
			}
			fragment := fragments[fragmentIndex]

			slog.Debug("Encrypting fragment for owner", "fragment_index", fragmentIndex, "assigned_owner_name", ownerInfo.Name)
			encrypted, err := crypto.EncryptFragment(encrypter, fragment)
			if err != nil {
				slog.Error("Failed to encrypt fragment",
					"fragment_index", fragmentIndex,
					"assigned_owner_name", ownerInfo.Name,
					"hybrid_key_path", ownerInfo.HybridPublicKey,
					"err", err)
				return 1
			}

			// Append the encrypted fragment to the list for this owner
			ownerEncryptedFragments[ownerInfo.Name].Fragments = append(ownerEncryptedFragments[ownerInfo.Name].Fragments, encrypted)
			slog.Debug("Appended encrypted fragment to owner's list", "fragment_index", fragmentIndex, "owner_name", ownerInfo.Name, "list_size_now", len(ownerEncryptedFragments[ownerInfo.Name].Fragments))
			fragmentIndex++
		}
	}
	// Sanity check: ensure all fragments were assigned
	if fragmentIndex != len(fragments) {
		slog.Error("Internal error: Fragment count mismatch after distribution", "assigned", fragmentIndex, "total", len(fragments))
		return 1
	}
	slog.Info("Finished encrypting and distributing fragments")

	// --- Construct Entry ---
	entry := &pb.Entry{
		Timestamp:      timestamppb.Now(),
		Key:            pushCfg.Key,
		Readers:        pushCfg.Readers, // Already a slice of strings
		OwnerFragments: ownerEncryptedFragments,
		Threshold:      int32(pushCfg.Threshold), // Store the threshold
		// Signature will be added next
	}
	slog.Debug("Constructed entry structure", "key", entry.Key, "timestamp", entry.Timestamp.AsTime(), "threshold", entry.Threshold)

	// --- Sign Entry ---
	slog.Debug("Signing entry with master key")
	err = crypto.SignEntry(masterSigner, entry)
	if err != nil {
		slog.Error("Failed to sign entry", "err", err)
		return 1
	}
	slog.Info("Entry signed successfully")

	// --- Push to Targets ---
	pushRequest := &pb.PushRequest{Entry: entry}
	var wg sync.WaitGroup
	successCount := 0
	errorCount := 0
	var mu sync.Mutex // To protect counters

	// Use a shared context for all push operations
	pushCtx, pushCancel := context.WithTimeout(context.Background(), 60*time.Second) // Overall timeout for pushing
	defer pushCancel()

	for _, target := range pushCfg.Targets {
		wg.Add(1)
		go func(targetEndpoint string) {
			defer wg.Done()
			slog.Info("Connecting to target node", "endpoint", targetEndpoint)
			// Use node.ConnectToPeer for consistency, though we don't need the full PeerNode struct here
			// We need a client connection. Let's simplify for push.
			// TODO: Refactor connection logic to be more reusable.
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

			slog.Info("Pushing entry to target", "endpoint", targetEndpoint, "key", pushCfg.Key)
			_, err = client.Push(callCtx, pushRequest) // Use callCtx

			mu.Lock()
			if err != nil {
				slog.Error("Failed to push entry to target", "endpoint", targetEndpoint, "key", pushCfg.Key, "err", err)
				errorCount++
			} else {
				slog.Info("Successfully pushed entry to target", "endpoint", targetEndpoint, "key", pushCfg.Key)
				successCount++
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	slog.Info("Push operation complete", "successful_targets", successCount, "failed_targets", errorCount)

	if errorCount > 0 {
		return 1 // Exit with error if any push failed
	}
	return 0 // Exit successfully
}
