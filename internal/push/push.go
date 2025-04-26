package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// OwnerInfo holds the IP and public key path for an owner node.
// Duplicated from old main, consider moving to a shared internal type if needed elsewhere.
type OwnerInfo struct {
	IP        string
	PublicKey string
}

// Config holds the specific configuration needed for the push subcommand.
type Config struct {
	MasterPrivateKey string   `kong:"name='master-key',required,help='Path to the master private key JSON file (for signing).'"`
	Owners           []string `kong:"name='owner',optional,help='Owner node info as IP=PublicKeyPath (e.g., 192.168.1.1=owner1_pub.json). Repeat for each owner. Can be sourced from --config.'"`
	Readers          []string `kong:"name='reader',required,help='IP address of a node allowed to read the secret. Repeat for each reader.'"`
	Key              string   `kong:"name='key',required,help='The key name for the secret.'"`
	Secret           string   `kong:"name='secret',required,help='The secret value to store.'"`
	Threshold        int      `kong:"name='threshold',short='t',required,help='Shamir threshold (number of fragments needed to reconstruct).'"`
	Parts            int      `kong:"name='parts',short='p',required,help='Total number of Shamir fragments to create (must match number of owners).'"`
	Targets          []string `kong:"name='target',optional,help='Endpoint address (host:port) of a target node to push to. Repeat for each target. Can be sourced from --config.'"`
	ConfigPath       string   `kong:"name='config',optional,help='Path to a configuration file to load parameters from (owners, targets).'"`
	// LogLevel is handled globally
}

// parseOwner parses the IP=PublicKeyPath string.
func parseOwner(ownerStr string) (*OwnerInfo, error) {
	parts := strings.SplitN(ownerStr, "=", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("invalid owner format, expected IP=PublicKeyPath, got %q", ownerStr)
	}
	// Basic IP validation could be added here if needed
	return &OwnerInfo{IP: parts[0], PublicKey: parts[1]}, nil
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
		for ip, peerCfg := range appCfg.Peers {
			if peerCfg.PublicKey == "" {
				// This check might be redundant if LoadConfig enforces it, but good defense.
				return nil, fmt.Errorf("peer %q in config file is missing public_key path", ip)
			}
			pushCfg.Owners = append(pushCfg.Owners, fmt.Sprintf("%s=%s", ip, peerCfg.PublicKey))
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
	if pushCfg.Parts != len(pushCfg.Owners) {
		slog.Error("Number of owners must match the number of parts", "parts", pushCfg.Parts, "owners", len(pushCfg.Owners))
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

	// --- Load Master Key ---
	slog.Debug("Loading master private key", "path", pushCfg.MasterPrivateKey)
	masterSigner, err := crypto.LoadMasterPrivateKeySigner(pushCfg.MasterPrivateKey)
	if err != nil {
		slog.Error("Failed to load master private key", "path", pushCfg.MasterPrivateKey, "err", err)
		return 1
	}
	slog.Info("Loaded master private key successfully")

	// --- Load Owner Public Keys (using parsed/derived owner info) ---
	ownerKeys := make(map[string]tink.HybridEncrypt) // Map: IP -> Encrypter
	ownerInfos := make([]*OwnerInfo, 0, len(pushCfg.Owners))
	ownerIPSet := make(map[string]struct{}) // To check for duplicate IPs
	for _, ownerStr := range pushCfg.Owners {
		ownerInfo, err := parseOwner(ownerStr)
		if err != nil {
			slog.Error("Failed to parse owner info", "input", ownerStr, "err", err)
			return 1
		}
		if _, exists := ownerIPSet[ownerInfo.IP]; exists {
			slog.Error("Duplicate owner IP specified", "ip", ownerInfo.IP)
			return 1
		}
		ownerIPSet[ownerInfo.IP] = struct{}{}
		ownerInfos = append(ownerInfos, ownerInfo) // Keep order for fragment assignment

		// Load the key using the path from the owner string
		slog.Debug("Loading owner public key", "ip", ownerInfo.IP, "path", ownerInfo.PublicKey)
		encrypter, err := crypto.LoadOwnerPublicKeyEncrypter(ownerInfo.PublicKey)
		if err != nil {
			slog.Error("Failed to load owner public key", "ip", ownerInfo.IP, "path", ownerInfo.PublicKey, "err", err)
			return 1
		}
		ownerKeys[ownerInfo.IP] = encrypter
		slog.Info("Loaded owner public key", "ip", ownerInfo.IP)
	}

	// --- Split Secret ---
	slog.Debug("Splitting secret", "parts", pushCfg.Parts, "threshold", pushCfg.Threshold)
	fragments, err := crypto.SplitSecret([]byte(pushCfg.Secret), pushCfg.Parts, pushCfg.Threshold)
	if err != nil {
		slog.Error("Failed to split secret", "err", err)
		return 1
	}
	slog.Info("Secret split into fragments", "count", len(fragments))

	// --- Encrypt Fragments ---
	encryptedFragments := make(map[string][]byte) // Map: Owner IP -> Encrypted Fragment
	if len(fragments) != len(ownerInfos) {
		// This should not happen if SplitSecret worked correctly
		slog.Error("Internal error: fragment count mismatch", "fragments", len(fragments), "owners", len(ownerInfos))
		return 1
	}

	for i, ownerInfo := range ownerInfos {
		fragment := fragments[i]
		encrypter := ownerKeys[ownerInfo.IP] // Assumes IP is unique and present
		slog.Debug("Encrypting fragment", "owner_ip", ownerInfo.IP, "fragment_index", i)
		encrypted, err := crypto.EncryptFragment(encrypter, fragment)
		if err != nil {
			slog.Error("Failed to encrypt fragment for owner", "owner_ip", ownerInfo.IP, "err", err)
			return 1
		}
		encryptedFragments[ownerInfo.IP] = encrypted
		slog.Info("Encrypted fragment", "owner_ip", ownerInfo.IP)
	}

	// --- Construct Entry ---
	entry := &pb.Entry{
		Timestamp:      timestamppb.Now(),
		Key:            pushCfg.Key,
		Readers:        pushCfg.Readers, // Already a slice of strings
		OwnerFragments: encryptedFragments,
		// Signature will be added next
	}
	slog.Debug("Constructed entry structure", "key", entry.Key, "timestamp", entry.Timestamp.AsTime())

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
