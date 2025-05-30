package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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
	MasterPrivateKeyPath string `kong:"name='master-private-key',xor='key-source',required,help='Path to the master private key JSON file (signing only).'"`
	MasterPrivateKey     string `kong:"name='master-private-key-value',xor='key-source',required,env='SSSMEMVAULT_MASTER_PRIVATE_KEY',help='The master private key JSON content (signing only). Can be supplied via SSSMEMVAULT_MASTER_PRIVATE_KEY environment variable.'"`

	Readers     []string `kong:"name='reader',required,help='Name of a node allowed to read the secret. Repeat for each reader.'"`
	Key         string   `kong:"name='key',required,help='The key name for the secret.'"`
	SecretPath  string   `kong:"name='secret-file',xor='secret-source',required,help='Path to a file containing the secret value.'"`
	SecretValue string   `kong:"name='secret',xor='secret-source',required,env='SSSMEMVAULT_SECRET',help='The secret value to store. Can be supplied via SSSMEMVAULT_SECRET environment variable.'"`
	Threshold   int      `kong:"name='threshold',short='t',required,help='Shamir threshold (number of fragments needed to reconstruct).'"`
	// Parts is now calculated based on sum of fragments_per_owner in config for owner peers.
	Targets    []string `kong:"name='target',optional,help='Endpoint address (host:port) of a target node to push to. Repeat for each target. Can be sourced from --config.'"`
	ConfigPath string   `kong:"name='config',required,help='Path to a configuration file to load parameters from (peers, targets).'"`
}

// loadConfigAndValidateInput loads the application configuration, derives targets if not specified,
// and validates essential input parameters from pushCfg.
func loadConfigAndValidateInput(pushCfg *Config) (*config.Config, error) {
	if pushCfg.ConfigPath == "" {
		return nil, errors.New("configuration file path is required")
	}

	slog.Info("Loading configuration file", "path", pushCfg.ConfigPath)
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
		for name, peerCfg := range appCfg.LoadedPeers {
			if peerCfg.Endpoint != "" {
				pushCfg.Targets = append(pushCfg.Targets, peerCfg.Endpoint)
			} else {
				slog.Debug("Skipping peer as target (no endpoint defined)", "peer_name", name)
			}
		}
		slog.Info("Using targets derived from config file", "count", len(pushCfg.Targets))
	}

	// Validate Inputs (Post-Config Load/Derivation)
	if pushCfg.Threshold <= 0 {
		return nil, fmt.Errorf("threshold must be positive, got %d", pushCfg.Threshold)
	}
	if len(pushCfg.Readers) == 0 {
		return nil, errors.New("at least one reader must be specified")
	}
	if len(pushCfg.Targets) == 0 {
		return nil, errors.New("no targets specified. Provide via --target flags or derive from --config file")
	}
	// Key presence is ensured by `kong:"required"`.
	// Secret presence is ensured by `xor` group `secret-source`.

	return appCfg, nil
}

// createEncryptedFragments splits the secret and encrypts fragments for each owner peer.
func createEncryptedFragments(secret string, threshold int, appCfg *config.Config) (map[string]*pb.FragmentList, error) {
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

// prepareAndSignEntry creates encrypted fragments, builds the protobuf Entry, and signs it.
func prepareAndSignEntry(pushCfg *Config, appCfg *config.Config, masterSigner tink.Signer, secretContent string) (*pb.Entry, error) {
	ownerEncryptedFragments, err := createEncryptedFragments(secretContent, pushCfg.Threshold, appCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare fragments: %w", err)
	}

	entry := &pb.Entry{
		Timestamp:      timestamppb.Now(),
		Key:            pushCfg.Key,
		Readers:        pushCfg.Readers,
		OwnerFragments: ownerEncryptedFragments,
		Threshold:      int32(pushCfg.Threshold),
	}
	slog.Debug("Constructed entry structure", "key", entry.Key, "timestamp", entry.Timestamp.AsTime(), "threshold", entry.Threshold)

	slog.Debug("Signing entry with master key")
	if err := crypto.SignEntry(masterSigner, entry); err != nil {
		return nil, fmt.Errorf("failed to sign entry: %w", err)
	}
	slog.Info("Entry signed successfully")
	return entry, nil
}

// distributeEntryToPeers pushes the signed entry to all target nodes concurrently.
func distributeEntryToPeers(targets []string, entry *pb.Entry) (successCount, errorCount int) {
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
func (pushCfg *Config) Run() error {
	slog.Info("Starting push operation...")

	appCfg, err := loadConfigAndValidateInput(pushCfg)
	if err != nil {
		slog.Error("Failed to load or validate configuration/input", "err", err)
		return err
	}

	var masterSigner tink.Signer
	if pushCfg.MasterPrivateKey != "" {
		slog.Debug("Loading master private key from value (environment variable or direct input)")
		masterSigner, err = crypto.LoadSignerFromValue(pushCfg.MasterPrivateKey)
		if err != nil {
			slog.Error("Failed to load master private key from value", "err", err)
			return err
		}
	} else { // pushCfg.MasterPrivateKeyPath must be present due to loadConfigAndValidateInput
		slog.Debug("Loading master private key (signer) from path", "path", pushCfg.MasterPrivateKeyPath)
		masterSigner, err = crypto.LoadSigner(pushCfg.MasterPrivateKeyPath)
		if err != nil {
			slog.Error("Failed to load master private key (signer) from path", "path", pushCfg.MasterPrivateKeyPath, "err", err)
			return err
		}
	}
	slog.Info("Loaded master private key (signer) successfully")

	var secretContent string
	switch {
	case pushCfg.SecretValue != "":
		secretContent = pushCfg.SecretValue
		slog.Debug("Using secret from direct value (flag or environment variable)")
	case pushCfg.SecretPath != "":
		slog.Debug("Loading secret from file", "path", pushCfg.SecretPath)
		data, err := os.ReadFile(pushCfg.SecretPath)
		if err != nil {
			slog.Error("Failed to read secret file", "path", pushCfg.SecretPath, "err", err)
			return fmt.Errorf("failed to read secret file %q: %w", pushCfg.SecretPath, err)
		}
		secretContent = string(data)
		slog.Info("Secret loaded from file successfully")
	default:
		// Probably not reachable but just in case
		return errors.New("no secret provided via --secret or --secret-file or SSSMEMVAULT_SECRET environment variable")
	}
	entry, err := prepareAndSignEntry(pushCfg, appCfg, masterSigner, secretContent)
	if err != nil {
		slog.Error("Failed to prepare or sign entry", "err", err)
		return err
	}

	_, errorCount := distributeEntryToPeers(pushCfg.Targets, entry)
	if errorCount > 0 {
		slog.Error("Push operation completed with errors", "failed_targets", errorCount)
		return err
	}

	slog.Info("Push operation completed successfully")
	return nil
}
