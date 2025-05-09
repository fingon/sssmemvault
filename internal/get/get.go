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
	// LogLevel is handled globally
	ClientName     string   `kong:"name='client-name',required,help='The name of this client (must match a key in target node configs).'"`
	PrivateKeyPath string   `kong:"name='private-key',required,help='Path to the client combined private keyset JSON file (signing + hybrid).'"`
	Key            string   `kong:"name='key',required,help='The key name for the secret to retrieve.'"`
	OutputFile     string   `kong:"name='output',short='o',help='Path to write the reconstructed secret to (stdout if not specified).'"`
	Targets        []string `kong:"name='target',optional,help='Endpoint address (host:port) of a target node to query. Repeat for each target. Can be sourced from --config.'"`
	ConfigPath     string   `kong:"name='config',required,help='Path to a configuration file to load parameters from (targets, peer info).'"` // Made required
}

// loadConfigAndValidateInput loads the application configuration, derives targets if not specified,
// and validates essential input parameters from getCfg.
func loadConfigAndValidateInput(getCfg *Config) (*config.Config, error) {
	if getCfg.ConfigPath == "" {
		return nil, errors.New("configuration file path is required")
	}

	slog.Info("Loading configuration file", "path", getCfg.ConfigPath)
	appCfg, err := config.LoadConfigIgnoreOwnKey(getCfg.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file %q: %w", getCfg.ConfigPath, err)
	}
	slog.Info("Configuration loaded successfully", "path", getCfg.ConfigPath)

	// Populate targets from config if not provided via flags
	if len(getCfg.Targets) == 0 {
		slog.Debug("Populating targets from config file")
		if appCfg.LoadedPeers == nil || len(appCfg.LoadedPeers) == 0 {
			return nil, errors.New("config file specified but contains no peers to use as targets")
		}
		for name, peerCfg := range appCfg.LoadedPeers {
			if peerCfg.Endpoint != "" {
				getCfg.Targets = append(getCfg.Targets, peerCfg.Endpoint)
			} else {
				slog.Debug("Skipping peer as target (no endpoint defined)", "peer_name", name)
			}
		}
		slog.Info("Using targets derived from config file", "count", len(getCfg.Targets))
	}

	// Validate Inputs
	if len(getCfg.Targets) == 0 {
		return nil, errors.New("no targets specified. Provide via --target flags or derive from --config file")
	}
	if getCfg.Key == "" || getCfg.ClientName == "" || getCfg.PrivateKeyPath == "" {
		return nil, errors.New("missing required arguments: key, client-name, or private-key")
	}
	return appCfg, nil
}

// loadClientKeys loads the signing and hybrid decryption primitives from the client's combined private keyset file.
func loadClientKeys(privateKeyPath string) (tink.Signer, tink.HybridDecrypt, error) {
	slog.Debug("Loading client private keyset", "path", privateKeyPath)

	// Load Signer
	clientSigner, err := crypto.LoadSigner(privateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client signer from keyset %q: %w", privateKeyPath, err)
	}
	slog.Info("Loaded client signer successfully")

	// Load Decrypter
	clientDecrypter, err := crypto.LoadDecrypter(privateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load client decrypter from keyset %q: %w", privateKeyPath, err)
	}
	slog.Info("Loaded client decrypter successfully")

	return clientSigner, clientDecrypter, nil
}

// findEntryOnNetwork finds the latest entry for a given key across the target nodes.
func findEntryOnNetwork(getCfg *Config, clientSigner tink.Signer, appCfg *config.Config) (*pb.Entry, error) {
	latestEntry, _, err := findLatestEntry(getCfg.Targets, getCfg.Key, getCfg.ClientName, clientSigner, appCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to find latest entry for key %q (client %s): %w", getCfg.Key, getCfg.ClientName, err)
	}
	if latestEntry == nil {
		return nil, fmt.Errorf("key %q not found on any target node", getCfg.Key)
	}
	slog.Info("Found latest entry", "key", latestEntry.Key, "timestamp", latestEntry.Timestamp.AsTime(), "threshold", latestEntry.Threshold)
	return latestEntry, nil
}

// determineOwnerEndpoints finds the gRPC endpoints for the given owner names using the loaded config.
func determineOwnerEndpoints(appCfg *config.Config, ownerNames []string) (map[string]string, error) {
	if appCfg == nil {
		return nil, errors.New("internal error: configuration not loaded")
	}
	ownerEndpoints := make(map[string]string) // Map: Owner Name -> Endpoint
	missingEndpoints := []string{}
	for _, ownerName := range ownerNames {
		peerCfg, ok := appCfg.LoadedPeers[ownerName]
		if !ok || peerCfg == nil {
			slog.Warn("Could not find config entry for owner", "owner_name", ownerName)
			missingEndpoints = append(missingEndpoints, ownerName+" (not found in config)")
			continue
		}
		if peerCfg.Endpoint == "" {
			slog.Warn("Owner found in config but has no endpoint defined", "owner_name", ownerName)
			missingEndpoints = append(missingEndpoints, ownerName+" (no endpoint)")
			continue
		}
		ownerEndpoints[ownerName] = peerCfg.Endpoint
		slog.Debug("Found endpoint for owner", "owner_name", ownerName, "endpoint", peerCfg.Endpoint)
	}
	if len(missingEndpoints) > 0 {
		// Use a config path field if available, or just the list
		return nil, fmt.Errorf("could not find endpoints for all owners in configuration file %q: %v", appCfg.PrivateKeyPath, missingEndpoints)
	}
	return ownerEndpoints, nil
}

// fetchEncryptedFragmentsFromOwners concurrently calls GetDecoded on all owner nodes.
func fetchEncryptedFragmentsFromOwners(ctx context.Context, ownerEndpoints map[string]string, clientName string, clientSigner tink.Signer, entry *pb.Entry) ([][]byte, map[string]error) {
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

// decryptReceivedFragments decrypts the received fragments using the client's hybrid key.
func decryptReceivedFragments(encryptedFragments [][]byte, clientDecrypter tink.HybridDecrypt) ([][]byte, int) {
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

// retrieveAndDecryptFragments orchestrates fetching and decrypting fragments.
func retrieveAndDecryptFragments(getCfg *Config, appCfg *config.Config, latestEntry *pb.Entry, clientSigner tink.Signer, clientDecrypter tink.HybridDecrypt) ([][]byte, error) {
	ownerNames := make([]string, 0, len(latestEntry.OwnerFragments))
	for name := range latestEntry.OwnerFragments {
		ownerNames = append(ownerNames, name)
	}
	sort.Strings(ownerNames) // Sort for consistent logging
	slog.Info("Identified owners for the entry", "key", getCfg.Key, "owners", ownerNames)

	ownerEndpoints, err := determineOwnerEndpoints(appCfg, ownerNames)
	if err != nil {
		return nil, fmt.Errorf("failed to determine owner endpoints: %w", err)
	}

	getDecodedCtx, getDecodedCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer getDecodedCancel()
	encryptedFragments, getDecodedErrors := fetchEncryptedFragmentsFromOwners(getDecodedCtx, ownerEndpoints, getCfg.ClientName, clientSigner, latestEntry)

	if len(getDecodedErrors) > 0 {
		slog.Error("Failed to retrieve fragments from some owners", "errors", getDecodedErrors)
		// Continue, maybe enough fragments were retrieved
	}
	if len(encryptedFragments) == 0 {
		return nil, errors.New("no encrypted fragments were retrieved successfully")
	}

	decryptedFragments, decryptionErrors := decryptReceivedFragments(encryptedFragments, clientDecrypter)
	if len(decryptedFragments) == 0 && decryptionErrors > 0 {
		return nil, fmt.Errorf("failed to decrypt any fragments (errors: %d)", decryptionErrors)
	}
	return decryptedFragments, nil
}

// reconstructAndOutputSecret combines decrypted fragments and writes the secret.
func reconstructAndOutputSecret(decryptedFragments [][]byte, threshold int32, outputPath string) error {
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

	appCfg, err := loadConfigAndValidateInput(getCfg)
	if err != nil {
		slog.Error("Failed to load or validate configuration/input", "err", err)
		return 1
	}

	clientSigner, clientDecrypter, err := loadClientKeys(getCfg.PrivateKeyPath)
	if err != nil {
		slog.Error("Failed to load client keys", "err", err)
		return 1
	}

	latestEntry, err := findEntryOnNetwork(getCfg, clientSigner, appCfg)
	if err != nil {
		slog.Error("Failed to find entry on network", "err", err)
		return 1
	}

	threshold := latestEntry.Threshold
	if threshold <= 0 {
		slog.Error("Invalid threshold found in entry", "key", getCfg.Key, "threshold", threshold)
		return 1
	}

	decryptedFragments, err := retrieveAndDecryptFragments(getCfg, appCfg, latestEntry, clientSigner, clientDecrypter)
	if err != nil {
		slog.Error("Failed to retrieve or decrypt fragments", "err", err)
		return 1
	}

	err = reconstructAndOutputSecret(decryptedFragments, threshold, getCfg.OutputFile)
	if err != nil {
		slog.Error("Failed to reconstruct secret or write output", "err", err)
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
