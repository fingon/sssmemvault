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
	ClientName            string   `kong:"name='client-name',required,help='The name of this client (must match a key in target node configs).'"`
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

// loadClientKeys loads the signing and hybrid private keys for the client.
func loadClientKeys(signingKeyPath, hybridKeyPath string) (tink.Signer, tink.HybridDecrypt, error) {
	slog.Debug("Loading client signing private key", "path", signingKeyPath)
	clientSigner, err := crypto.LoadPrivateKeySigner(signingKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client signing private key %q: %w", signingKeyPath, err)
	}
	slog.Info("Loaded client signing private key successfully")

	slog.Debug("Loading client hybrid private key", "path", hybridKeyPath)
	clientDecrypter, err := crypto.LoadClientHybridPrivateKey(hybridKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client hybrid private key %q: %w", hybridKeyPath, err)
	}
	slog.Info("Loaded client hybrid private key successfully")

	return clientSigner, clientDecrypter, nil
}

// determineOwnerEndpoints finds the gRPC endpoints for the given owner names using the loaded config.
func determineOwnerEndpoints(appCfg *config.Config, ownerNames []string, configPath string) (map[string]string, error) {
	if appCfg == nil {
		return nil, errors.New("cannot determine owner endpoints without a configuration file (--config)")
	}
	ownerEndpoints := make(map[string]string) // Map: Owner Name -> Endpoint
	for _, ownerName := range ownerNames {
		peerCfg, ok := appCfg.LoadedPeers[ownerName] // Use LoadedPeers which has pointers
		if !ok || peerCfg == nil || peerCfg.Endpoint == "" {
			return nil, fmt.Errorf("could not find endpoint for owner %q in configuration file %q", ownerName, configPath)
		}
		ownerEndpoints[ownerName] = peerCfg.Endpoint
		slog.Debug("Found endpoint for owner", "owner_name", ownerName, "endpoint", peerCfg.Endpoint)
	}
	return ownerEndpoints, nil
}

// fetchEncryptedFragments concurrently calls GetDecoded on all owner nodes.
func fetchEncryptedFragments(ctx context.Context, ownerEndpoints map[string]string, clientName string, clientSigner tink.Signer, entry *pb.Entry) ([][]byte, map[string]error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	encryptedFragments := make([][]byte, 0, len(ownerEndpoints)) // Store encrypted fragments first
	getDecodedErrors := make(map[string]error)                   // Map: Owner Name -> Error

	getDecodedRequest := &pb.GetDecodedRequest{
		Key:       entry.Key,
		Timestamp: entry.Timestamp,
	}

	slog.Info("Requesting encrypted fragments from owner nodes", "owners", ownerEndpoints)
	for ownerName, endpoint := range ownerEndpoints {
		wg.Add(1)
		go func(name, ep string) {
			defer wg.Done()
			slog.Debug("Connecting to owner node for GetDecoded", "owner_name", name, "endpoint", ep)
			conn, err := node.DialPeer(ctx, ep)
			if err != nil {
				slog.Warn("Failed to connect to owner node", "owner_name", name, "endpoint", ep, "err", err)
				mu.Lock()
				getDecodedErrors[name] = err
				mu.Unlock()
				return
			}
			defer func() {
				if err := conn.Close(); err != nil {
					slog.Warn("Error closing connection to owner node", "owner_name", name, "endpoint", ep, "err", err)
				}
			}()

			client := pb.NewSssMemVaultClient(conn)
			callCtx, callCancel := context.WithTimeout(ctx, 30*time.Second) // Timeout per call
			defer callCancel()

			slog.Debug("Calling GetDecoded on owner node", "owner_name", name, "key", entry.Key)
			resp, err := node.CallGetDecodedFromClient(callCtx, client, clientName, clientSigner, getDecodedRequest)

			mu.Lock()
			switch {
			case err != nil:
				slog.Warn("Failed to get encrypted fragments from owner", "owner_name", name, "key", entry.Key, "err", err)
				getDecodedErrors[name] = err
			case resp == nil || len(resp.EncryptedFragments) == 0:
				slog.Warn("Received empty encrypted fragment list from owner", "owner_name", name, "key", entry.Key)
				getDecodedErrors[name] = errors.New("received empty encrypted fragment list")
			default:
				slog.Info("Successfully received encrypted fragments", "owner_name", name, "key", entry.Key, "count", len(resp.EncryptedFragments))
				encryptedFragments = append(encryptedFragments, resp.EncryptedFragments...)
			}
			mu.Unlock()
		}(ownerName, endpoint)
	}

	wg.Wait()
	return encryptedFragments, getDecodedErrors
}

// decryptFragments decrypts the received fragments using the client's hybrid key.
func decryptFragments(encryptedFragments [][]byte, clientDecrypter tink.HybridDecrypt) ([][]byte, int) {
	slog.Info("Decrypting received fragments", "count", len(encryptedFragments))
	decryptedFragments := make([][]byte, 0, len(encryptedFragments))
	decryptionErrors := 0
	for i, encFrag := range encryptedFragments {
		decFrag, err := crypto.DecryptFragment(clientDecrypter, encFrag)
		if err != nil {
			slog.Warn("Failed to decrypt fragment", "index", i, "err", err)
			decryptionErrors++
			continue // Do not add failed fragment
		}
		decryptedFragments = append(decryptedFragments, decFrag)
	}
	return decryptedFragments, decryptionErrors
}

// combineAndOutput combines the decrypted fragments and writes the result.
func combineAndOutput(decryptedFragments [][]byte, threshold int32, outputPath string) error {
	if len(decryptedFragments) < int(threshold) {
		return fmt.Errorf("not enough fragments decrypted successfully to meet threshold (got %d, need %d)",
			len(decryptedFragments), threshold)
	}
	slog.Info("Successfully decrypted fragments", "count", len(decryptedFragments), "required_threshold", threshold)

	slog.Info("Attempting to combine decrypted fragments", "count", len(decryptedFragments))
	reconstructedSecret, err := crypto.CombineFragments(decryptedFragments)
	if err != nil {
		return fmt.Errorf("failed to combine decrypted fragments (provided %d): %w", len(decryptedFragments), err)
	}
	slog.Info("Successfully reconstructed secret")

	// Output Secret
	if outputPath == "" || outputPath == "-" {
		slog.Debug("Writing secret to stdout")
		_, err = os.Stdout.Write(reconstructedSecret)
		if err == nil {
			_, _ = os.Stdout.WriteString("\n") // Add newline for terminal
		}
	} else {
		slog.Info("Writing secret to output file", "path", outputPath)
		err = os.WriteFile(outputPath, reconstructedSecret, 0o600) // Restrictive permissions
	}

	if err != nil {
		return fmt.Errorf("failed to write reconstructed secret: %w", err)
	}
	return nil
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
	// Other input validations... (key, clientName, key paths)
	if getCfg.Key == "" || getCfg.ClientName == "" || getCfg.SigningPrivateKeyPath == "" || getCfg.HybridPrivateKeyPath == "" {
		slog.Error("Missing required arguments: key, client-name, signing-private-key, or hybrid-private-key")
		return 1
	}

	// --- Load Client Keys ---
	clientSigner, clientDecrypter, err := loadClientKeys(getCfg.SigningPrivateKeyPath, getCfg.HybridPrivateKeyPath)
	if err != nil {
		slog.Error("Failed to load client keys", "err", err)
		return 1
	}

	// --- Find Latest Entry Across Targets ---
	latestEntry, _, err := findLatestEntry(getCfg.Targets, getCfg.Key, getCfg.ClientName, clientSigner, appCfg)
	if err != nil {
		slog.Error("Failed to find latest entry for key", "key", getCfg.Key, "client_name", getCfg.ClientName, "err", err)
		return 1
	}
	if latestEntry == nil {
		slog.Error("Key not found on any target node", "key", getCfg.Key)
		return 1
	}
	slog.Info("Found latest entry", "key", latestEntry.Key, "timestamp", latestEntry.Timestamp.AsTime(), "threshold", latestEntry.Threshold)

	// --- Determine Owners and Threshold ---
	threshold := latestEntry.Threshold
	if threshold <= 0 {
		slog.Error("Invalid threshold found in entry", "key", getCfg.Key, "threshold", threshold)
		return 1
	}
	ownerNames := make([]string, 0, len(latestEntry.OwnerFragments))
	for name := range latestEntry.OwnerFragments {
		ownerNames = append(ownerNames, name)
	}
	sort.Strings(ownerNames)
	slog.Info("Identified owners for the entry", "key", getCfg.Key, "owners", ownerNames)

	// --- Determine Owner Endpoints ---
	ownerEndpoints, err := determineOwnerEndpoints(appCfg, ownerNames, getCfg.ConfigPath)
	if err != nil {
		slog.Error("Failed to determine owner endpoints", "err", err)
		return 1
	}

	// --- Fetch Encrypted Fragments ---
	getDecodedCtx, getDecodedCancel := context.WithTimeout(context.Background(), 60*time.Second) // Timeout for all GetDecoded calls
	defer getDecodedCancel()
	encryptedFragments, getDecodedErrors := fetchEncryptedFragments(getDecodedCtx, ownerEndpoints, getCfg.ClientName, clientSigner, latestEntry)

	if len(getDecodedErrors) > 0 {
		slog.Error("Failed to retrieve fragments from some owners", "errors", getDecodedErrors)
		// Continue anyway, maybe enough fragments were retrieved
	}
	if len(encryptedFragments) == 0 {
		slog.Error("No encrypted fragments were retrieved successfully.")
		return 1
	}

	// --- Decrypt Fragments ---
	decryptedFragments, decryptionErrors := decryptFragments(encryptedFragments, clientDecrypter)
	if len(decryptedFragments) == 0 && decryptionErrors > 0 {
		slog.Error("Failed to decrypt any fragments", "errors", decryptionErrors)
		return 1
	}

	// --- Combine and Output ---
	err = combineAndOutput(decryptedFragments, threshold, getCfg.OutputFile)
	if err != nil {
		slog.Error("Failed to combine fragments or write output", "err", err)
		return 1
	}

	slog.Info("Get operation completed successfully")
	return 0
}

// findLatestTimestampAndSource queries targets to find the latest timestamp for a key and the target holding it.
func findLatestTimestampAndSource(ctx context.Context, targets []string, key, clientName string, clientSigner tink.Signer) (*timestamppb.Timestamp, string, error) {
	var latestTimestamp *timestamppb.Timestamp
	var sourceTarget string
	var mu sync.Mutex
	var wg sync.WaitGroup
	listErrors := make(map[string]error)

	slog.Info("Querying targets to find latest timestamp", "key", key, "targets", targets)

	for _, target := range targets {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			slog.Debug("Connecting to target for List", "endpoint", endpoint)
			conn, err := node.DialPeer(ctx, endpoint)
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
			callCtx, callCancel := context.WithTimeout(ctx, 15*time.Second)
			defer callCancel()

			slog.Debug("Calling List on target", "endpoint", endpoint, "client_name", clientName)
			listResp, err := node.CallListFromClient(callCtx, client, clientName, clientSigner, &pb.ListRequest{})
			if err != nil {
				slog.Warn("Failed to call List on target", "endpoint", endpoint, "client_name", clientName, "err", err)
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

	return latestTimestamp, sourceTarget, nil
}

// fetchFullEntry retrieves the complete entry from a specific target.
func fetchFullEntry(ctx context.Context, targetEndpoint, key, clientName string, timestamp *timestamppb.Timestamp, clientSigner tink.Signer) (*pb.Entry, error) {
	slog.Info("Fetching full latest entry", "key", key, "timestamp", timestamp.AsTime(), "target", targetEndpoint)
	conn, err := node.DialPeer(ctx, targetEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target %q to get full entry: %w", targetEndpoint, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Warn("Error closing connection to target node during Get", "target", targetEndpoint, "err", err)
		}
	}()

	client := pb.NewSssMemVaultClient(conn)
	callCtx, callCancel := context.WithTimeout(ctx, 15*time.Second)
	defer callCancel()

	getRequest := &pb.GetRequest{Key: key, Timestamp: timestamp}
	slog.Debug("Calling Get on target", "endpoint", targetEndpoint, "client_name", clientName, "key", key)
	getResp, err := node.CallGetFromClient(callCtx, client, clientName, clientSigner, getRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get full entry for key %q from target %q (client %s): %w", key, targetEndpoint, clientName, err)
	}
	if getResp == nil || getResp.Entry == nil {
		return nil, fmt.Errorf("received empty response when getting full entry for key %q from target %q", key, targetEndpoint)
	}

	// Optional: Verify master signature again? Store already does this.
	// err = crypto.VerifyEntrySignature(appCfg.MasterPubKey, getResp.Entry) // Need appCfg for MasterPubKey
	// if err != nil { ... }

	return getResp.Entry, nil
}

// findLatestEntry queries targets to find the latest timestamp for a key and returns the full entry.
// It requires the clientName for authenticating requests to the target nodes.
// The appCfg parameter is currently unused but kept for potential future use (e.g., master key verification).
func findLatestEntry(targets []string, key, clientName string, clientSigner tink.Signer, _ *config.Config) (*pb.Entry, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Find the latest timestamp and the target holding it
	latestTimestamp, sourceTarget, err := findLatestTimestampAndSource(ctx, targets, key, clientName, clientSigner)
	if err != nil {
		return nil, "", err // Error already contains context
	}
	if latestTimestamp == nil {
		// Should have been caught by findLatestTimestampAndSource, but double-check
		return nil, "", fmt.Errorf("key %q not found (internal error)", key)
	}

	// 2. Fetch the full entry from the source target
	latestEntry, err := fetchFullEntry(ctx, sourceTarget, key, clientName, latestTimestamp, clientSigner)
	if err != nil {
		return nil, "", err // Error already contains context
	}

	return latestEntry, sourceTarget, nil
}
