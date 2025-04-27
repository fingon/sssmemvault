package get

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/fingon/sssmemvault/internal/node"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config holds the specific configuration needed for the get subcommand.
type Config struct {
	SigningPrivateKeyPath string   `kong:"name='signing-private-key',required,help='Path to the client private key JSON file (for signing requests).'"`
	HybridPrivateKeyPath  string   `kong:"name='hybrid-private-key',required,help='Path to the client private key JSON file (for decrypting received fragments).'"`
	Key                   string   `kong:"name='key',required,help='The key name for the secret to retrieve.'"`
	OutputFile            string   `kong:"name='output',short='o',help='Path to write the reconstructed secret to (stdout if not specified).'"`
	Targets               []string `kong:"name='target',optional,help='Endpoint address (host:port) of a target node to query. Repeat for each target. Can be sourced from --config.'"`
	ConfigPath            string   `kong:"name='config',optional,help='Path to a configuration file to load parameters from (targets, peer info).'"`
	// LogLevel is handled globally
}

// loadConfigAndDeriveParams loads the configuration file if specified and updates
// the get Config struct with targets derived from the config if they weren't
// provided via command-line flags. It returns the loaded app config or nil.
func loadConfigAndDeriveParams(getCfg *Config) (*config.Config, error) {
	if getCfg.ConfigPath == "" {
		return nil, nil // No config file specified, nothing to do
	}

	slog.Info("Loading configuration file", "path", getCfg.ConfigPath)
	// Load config but ignore private key errors as we use a specific client key
	appCfg, err := config.LoadConfigIgnoreOwnKey(getCfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file %q: %w", getCfg.ConfigPath, err)
	}
	slog.Info("Configuration loaded successfully", "path", getCfg.ConfigPath)

	// Populate targets from config if not provided via flags
	if len(getCfg.Targets) == 0 {
		slog.Debug("Populating targets from config file")
		if appCfg.Peers == nil || len(appCfg.Peers) == 0 {
			return nil, errors.New("config file specified but contains no peers to use as targets")
		}
		// Endpoints are validated during config.LoadConfig, so we assume they exist here.
		for _, peerCfg := range appCfg.Peers {
			getCfg.Targets = append(getCfg.Targets, peerCfg.Endpoint)
		}
		slog.Info("Using targets derived from config file", "count", len(getCfg.Targets))
	}
	return appCfg, nil
}

// Run executes the get operation.
func Run(getCfg *Config) int {
	slog.Info("Starting get operation...")

	// --- Load Config if specified and derive parameters ---
	appCfg, err := loadConfigAndDeriveParams(getCfg) // appCfg might be nil
	if err != nil {
		slog.Error("Failed to load or process configuration", "err", err)
		return 1
	}

	// --- Validate Inputs ---
	if len(getCfg.Targets) == 0 {
		slog.Error("No targets specified. Provide via --target flags or --config file.")
		return 1
	}
	if getCfg.Key == "" {
		slog.Error("Key cannot be empty.")
		return 1
	}
	if getCfg.SigningPrivateKeyPath == "" {
		slog.Error("Client signing private key path cannot be empty.")
		return 1
	}
	if getCfg.HybridPrivateKeyPath == "" {
		slog.Error("Client hybrid private key path cannot be empty.")
		return 1
	}

	// --- Load Client Keys ---
	slog.Debug("Loading client signing private key", "path", getCfg.SigningPrivateKeyPath)
	clientSigner, err := crypto.LoadPrivateKeySigner(getCfg.SigningPrivateKeyPath)
	if err != nil {
		slog.Error("Failed to load client signing private key", "path", getCfg.SigningPrivateKeyPath, "err", err)
		return 1
	}
	slog.Info("Loaded client signing private key successfully")

	slog.Debug("Loading client hybrid private key", "path", getCfg.HybridPrivateKeyPath)
	clientDecrypter, err := crypto.LoadClientHybridPrivateKey(getCfg.HybridPrivateKeyPath)
	if err != nil {
		slog.Error("Failed to load client hybrid private key", "path", getCfg.HybridPrivateKeyPath, "err", err)
		return 1
	}
	slog.Info("Loaded client hybrid private key successfully")

	// --- Connect to Targets and Find Latest Entry ---
	// We need to find the latest timestamp for the key across all targets.
	// We also need the full entry to know the owners and the required threshold.
	latestEntry, targetEndpointForGet, err := findLatestEntry(getCfg.Targets, getCfg.Key, clientSigner, appCfg)
	if err != nil {
		slog.Error("Failed to find latest entry for key", "key", getCfg.Key, "err", err)
		return 1
	}
	if latestEntry == nil {
		slog.Error("Key not found on any target node", "key", getCfg.Key)
		return 1 // Or a different exit code for not found?
	}
	slog.Info("Found latest entry", "key", latestEntry.Key, "timestamp", latestEntry.Timestamp.AsTime(), "threshold", latestEntry.Threshold, "source_node", targetEndpointForGet)

	// --- Determine Owners and Threshold ---
	threshold := latestEntry.Threshold
	if threshold <= 0 {
		slog.Error("Invalid threshold found in entry", "key", getCfg.Key, "threshold", threshold)
		return 1
	}

	ownerIPs := make([]string, 0, len(latestEntry.OwnerFragments))
	for ip := range latestEntry.OwnerFragments {
		ownerIPs = append(ownerIPs, ip)
	}
	sort.Strings(ownerIPs) // Consistent ordering for logging/debugging

	slog.Info("Identified owners for the entry", "key", getCfg.Key, "owners", ownerIPs)

	// --- Determine Owner Endpoints ---
	// We need the gRPC endpoints for the owner IPs.
	// Get them from the loaded config file if available, otherwise fail.
	if appCfg == nil {
		slog.Error("Cannot determine owner endpoints without a configuration file (--config)")
		return 1
	}
	ownerEndpoints := make(map[string]string) // Map: Owner IP -> Endpoint
	for _, ownerIP := range ownerIPs {
		peerCfg, ok := appCfg.Peers[ownerIP]
		if !ok || peerCfg.Endpoint == "" {
			slog.Error("Could not find endpoint for owner in configuration file", "owner_ip", ownerIP, "config_path", getCfg.ConfigPath)
			return 1
		}
		ownerEndpoints[ownerIP] = peerCfg.Endpoint
		slog.Debug("Found endpoint for owner", "owner_ip", ownerIP, "endpoint", peerCfg.Endpoint)
	}

	// --- Call GetDecoded on Owner Nodes Concurrently ---
	slog.Info("Requesting encrypted fragments from owner nodes", "owners", ownerIPs)
	var wg sync.WaitGroup
	var mu sync.Mutex
	encryptedFragments := make([][]byte, 0, len(ownerIPs)) // Store encrypted fragments first
	getDecodedErrors := make(map[string]error)

	getDecodedCtx, getDecodedCancel := context.WithTimeout(context.Background(), 60*time.Second) // Timeout for all GetDecoded calls
	defer getDecodedCancel()

	getDecodedRequest := &pb.GetDecodedRequest{
		Key:       latestEntry.Key,
		Timestamp: latestEntry.Timestamp,
	}

	for _, ownerIP := range ownerIPs {
		wg.Add(1)
		go func(ip, endpoint string) {
			defer wg.Done()
			slog.Debug("Connecting to owner node for GetDecoded", "owner_ip", ip, "endpoint", endpoint)
			// Reuse connection logic if possible, or simplify
			conn, err := node.DialPeer(getDecodedCtx, endpoint)
			if err != nil {
				slog.Warn("Failed to connect to owner node", "owner_ip", ip, "endpoint", endpoint, "err", err)
				mu.Lock()
				getDecodedErrors[ip] = err
				mu.Unlock()
				return
			}
			defer func() {
				if err := conn.Close(); err != nil {
					slog.Warn("Error closing connection to owner node", "owner_ip", ip, "endpoint", endpoint, "err", err)
				}
			}()

			client := pb.NewSssMemVaultClient(conn)
			callCtx, callCancel := context.WithTimeout(getDecodedCtx, 30*time.Second) // Timeout per call
			defer callCancel()

			slog.Debug("Calling GetDecoded on owner node", "owner_ip", ip, "key", getCfg.Key)
			resp, err := node.CallGetDecodedFromClient(callCtx, client, clientSigner, getDecodedRequest) // Use specific client call helper

			mu.Lock()
			switch {
			case err != nil:
				slog.Warn("Failed to get encrypted fragments from owner", "owner_ip", ip, "key", getCfg.Key, "err", err)
				getDecodedErrors[ip] = err
			case resp == nil || len(resp.EncryptedFragments) == 0: // Check the correct field name (plural)
				slog.Warn("Received empty encrypted fragment list from owner", "owner_ip", ip, "key", getCfg.Key)
				getDecodedErrors[ip] = errors.New("received empty encrypted fragment list")
			default:
				slog.Info("Successfully received encrypted fragments", "owner_ip", ip, "key", getCfg.Key, "count", len(resp.EncryptedFragments))
				// Add all received fragments to the list
				encryptedFragments = append(encryptedFragments, resp.EncryptedFragments...)
			}
			mu.Unlock()
		}(ownerIP, ownerEndpoints[ownerIP])
	}

	wg.Wait()

	// --- Combine Fragments ---
	if len(getDecodedErrors) > 0 {
		slog.Error("Failed to retrieve fragments from some owners", "errors", getDecodedErrors)
		// Continue to decryption and combination attempt
	}

	if len(encryptedFragments) == 0 {
		slog.Error("No encrypted fragments were retrieved successfully.")
		return 1
	}

	// --- Decrypt Fragments ---
	slog.Info("Decrypting received fragments", "count", len(encryptedFragments))
	decryptedFragments := make([][]byte, 0, len(encryptedFragments))
	decryptionErrors := 0
	for i, encFrag := range encryptedFragments {
		decFrag, err := crypto.DecryptFragment(clientDecrypter, encFrag)
		if err != nil {
			slog.Warn("Failed to decrypt fragment", "index", i, "err", err)
			decryptionErrors++
			// Do not add failed fragment to the list for combination
			continue
		}
		decryptedFragments = append(decryptedFragments, decFrag)
	}

	if len(decryptedFragments) < int(threshold) {
		slog.Error("Not enough fragments decrypted successfully to meet threshold",
			"decrypted_count", len(decryptedFragments),
			"required_threshold", threshold,
			"retrieved_count", len(encryptedFragments),
			"decryption_errors", decryptionErrors)
		return 1
	}
	slog.Info("Successfully decrypted fragments", "count", len(decryptedFragments), "required_threshold", threshold)

	// --- Combine Decrypted Fragments ---
	slog.Info("Attempting to combine decrypted fragments", "count", len(decryptedFragments))
	reconstructedSecret, err := crypto.CombineFragments(decryptedFragments)
	if err != nil {
		slog.Error("Failed to combine decrypted fragments", "err", err, "fragments_provided", len(decryptedFragments))
		// This might indicate an issue with the fragments themselves or the threshold logic
		return 1
	}
	slog.Info("Successfully reconstructed secret")

	// --- Output Secret ---
	if getCfg.OutputFile == "" || getCfg.OutputFile == "-" {
		slog.Debug("Writing secret to stdout")
		_, err = os.Stdout.Write(reconstructedSecret)
		if err == nil {
			// Add a newline if writing to stdout for better terminal behavior
			_, _ = os.Stdout.WriteString("\n")
		}
	} else {
		slog.Info("Writing secret to output file", "path", getCfg.OutputFile)
		err = os.WriteFile(getCfg.OutputFile, reconstructedSecret, 0o600) // Restrictive permissions
	}

	if err != nil {
		slog.Error("Failed to write reconstructed secret", "err", err)
		return 1
	}

	slog.Info("Get operation completed successfully")
	return 0
}

// findLatestEntry queries targets to find the latest timestamp for a key and returns the full entry.
// The appCfg parameter is currently unused but kept for potential future use (e.g., master key verification).
func findLatestEntry(targets []string, key string, clientSigner tink.Signer, _ *config.Config) (*pb.Entry, string, error) {
	var latestTimestamp *timestamppb.Timestamp
	var latestEntry *pb.Entry
	var sourceTarget string
	var mu sync.Mutex
	var wg sync.WaitGroup
	listErrors := make(map[string]error)

	listCtx, listCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer listCancel()

	slog.Info("Querying targets to find latest entry", "key", key, "targets", targets)

	for _, target := range targets {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			slog.Debug("Connecting to target for List", "endpoint", endpoint)
			conn, err := node.DialPeer(listCtx, endpoint)
			if err != nil {
				slog.Warn("Failed to connect to target for List", "endpoint", endpoint, "err", err)
				mu.Lock()
				listErrors[endpoint] = err
				mu.Unlock()
				return
			}
			defer func() {
				if err := conn.Close(); err != nil {
					slog.Warn("Error closing connection to target node during List", "endpoint", endpoint, "err", err)
				}
			}()

			client := pb.NewSssMemVaultClient(conn)
			callCtx, callCancel := context.WithTimeout(listCtx, 15*time.Second)
			defer callCancel()

			slog.Debug("Calling List on target", "endpoint", endpoint)
			listResp, err := node.CallListFromClient(callCtx, client, clientSigner, &pb.ListRequest{})
			if err != nil {
				slog.Warn("Failed to call List on target", "endpoint", endpoint, "err", err)
				mu.Lock()
				listErrors[endpoint] = err
				mu.Unlock()
				return
			}

			// Find the specific key in the response
			for _, meta := range listResp.Entries {
				if meta.Key == key {
					mu.Lock()
					if latestTimestamp == nil || meta.Timestamp.AsTime().After(latestTimestamp.AsTime()) {
						slog.Debug("Found newer timestamp for key", "key", key, "timestamp", meta.Timestamp.AsTime(), "target", endpoint)
						latestTimestamp = meta.Timestamp
						sourceTarget = endpoint // Track which target has the latest known timestamp
					}
					mu.Unlock()
					break // Found the key, move to next target
				}
			}
		}(target)
	}
	wg.Wait()

	if latestTimestamp == nil {
		if len(listErrors) > 0 {
			return nil, "", fmt.Errorf("key %q not found and failed to query some targets: %v", key, listErrors)
		}
		return nil, "", fmt.Errorf("key %q not found on any target", key)
	}

	// Now fetch the full entry from the target that had the latest timestamp
	slog.Info("Fetching full latest entry", "key", key, "timestamp", latestTimestamp.AsTime(), "target", sourceTarget)
	conn, err := node.DialPeer(listCtx, sourceTarget) // Reuse listCtx
	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to target %q to get full entry: %w", sourceTarget, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Warn("Error closing connection to target node during Get", "target", sourceTarget, "err", err)
		}
	}()

	client := pb.NewSssMemVaultClient(conn)
	callCtx, callCancel := context.WithTimeout(listCtx, 15*time.Second)
	defer callCancel()

	getRequest := &pb.GetRequest{Key: key, Timestamp: latestTimestamp}
	getResp, err := node.CallGetFromClient(callCtx, client, clientSigner, getRequest)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get full entry for key %q from target %q: %w", key, sourceTarget, err)
	}
	if getResp == nil || getResp.Entry == nil {
		return nil, "", fmt.Errorf("received empty response when getting full entry for key %q from target %q", key, sourceTarget)
	}

	// Optional: Verify master signature again? Store already does this.
	// err = crypto.VerifyEntrySignature(appCfg.MasterPubKey, getResp.Entry) // Need appCfg for MasterPubKey
	// if err != nil { ... }

	latestEntry = getResp.Entry
	return latestEntry, sourceTarget, nil
}
