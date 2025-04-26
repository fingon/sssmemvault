package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fingon/sssmemvault/internal/crypto"
	pb "github.com/fingon/sssmemvault/proto"
	_ "github.com/google/tink/go/hybrid/subtle"    // Register DHKEM
	_ "github.com/google/tink/go/signature/subtle" // Register ED25519, ECDSA
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// OwnerInfo holds the IP and public key path for an owner node.
type OwnerInfo struct {
	IP        string
	PublicKey string
}

// CLI holds the command-line arguments for the push tool.
type CLI struct {
	MasterPrivateKey string   `kong:"name='master-key',required,help='Path to the master private key JSON file (for signing).'"`
	Owners           []string `kong:"name='owner',required,help='Owner node info as IP=PublicKeyPath (e.g., 192.168.1.1=owner1_pub.json). Repeat for each owner.'"`
	Readers          []string `kong:"name='reader',required,help='IP address of a node allowed to read the secret. Repeat for each reader.'"`
	Key              string   `kong:"name='key',required,help='The key name for the secret.'"`
	Secret           string   `kong:"name='secret',required,help='The secret value to store.'"`
	Threshold        int      `kong:"name='threshold',short='t',required,help='Shamir threshold (number of fragments needed to reconstruct).'"`
	Parts            int      `kong:"name='parts',short='p',required,help='Total number of Shamir fragments to create (must match number of owners).'"`
	Targets          []string `kong:"name='target',required,help='Endpoint address (host:port) of a target node to push to. Repeat for each target.'"`
	LogLevel         string   `kong:"name='loglevel',enum='debug,info,warn,error',default='info',help='Log level (debug, info, warn, error).'"`
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

func main() {
	var cli CLI
	kctx := kong.Parse(&cli)

	// --- Setup Logging ---
	var level slog.Level
	switch cli.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", cli.LogLevel)
		os.Exit(1)
	}
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}) // Log to stderr for tools
	slog.SetDefault(slog.New(logHandler))

	// --- Register Tink Primitives ---
	// Ensure necessary Tink primitives are registered via side-effect imports.
	// Explicit registration calls are generally not needed if using the standard Tink setup.
	// signature.Register()
	// hybrid.Register()
	slog.Debug("Tink primitives should be registered via imports")

	// --- Validate Inputs ---
	if cli.Parts != len(cli.Owners) {
		slog.Error("Number of owners must match the number of parts", "parts", cli.Parts, "owners", len(cli.Owners))
		kctx.Exit(1)
	}
	if cli.Threshold > cli.Parts {
		slog.Error("Threshold cannot be greater than the number of parts", "threshold", cli.Threshold, "parts", cli.Parts)
		kctx.Exit(1)
	}
	if cli.Threshold <= 0 {
		slog.Error("Threshold must be positive", "threshold", cli.Threshold)
		kctx.Exit(1)
	}
	if len(cli.Readers) == 0 {
		slog.Error("At least one reader IP must be specified")
		kctx.Exit(1)
	}
	if len(cli.Targets) == 0 {
		slog.Error("At least one target node endpoint must be specified")
		kctx.Exit(1)
	}

	// --- Load Master Key ---
	slog.Debug("Loading master private key", "path", cli.MasterPrivateKey)
	masterSigner, err := crypto.LoadMasterPrivateKeySigner(cli.MasterPrivateKey)
	if err != nil {
		slog.Error("Failed to load master private key", "path", cli.MasterPrivateKey, "err", err)
		kctx.Exit(1)
	}
	slog.Info("Loaded master private key successfully")

	// --- Load Owner Public Keys ---
	ownerKeys := make(map[string]tink.HybridEncrypt) // Map: IP -> Encrypter
	ownerInfos := make([]*OwnerInfo, 0, len(cli.Owners))
	for _, ownerStr := range cli.Owners {
		ownerInfo, err := parseOwner(ownerStr)
		if err != nil {
			slog.Error("Failed to parse owner info", "input", ownerStr, "err", err)
			kctx.Exit(1)
		}
		ownerInfos = append(ownerInfos, ownerInfo) // Keep order for fragment assignment

		slog.Debug("Loading owner public key", "ip", ownerInfo.IP, "path", ownerInfo.PublicKey)
		encrypter, err := crypto.LoadOwnerPublicKeyEncrypter(ownerInfo.PublicKey)
		if err != nil {
			slog.Error("Failed to load owner public key", "ip", ownerInfo.IP, "path", ownerInfo.PublicKey, "err", err)
			kctx.Exit(1)
		}
		ownerKeys[ownerInfo.IP] = encrypter
		slog.Info("Loaded owner public key", "ip", ownerInfo.IP)
	}

	// --- Split Secret ---
	slog.Debug("Splitting secret", "parts", cli.Parts, "threshold", cli.Threshold)
	fragments, err := crypto.SplitSecret([]byte(cli.Secret), cli.Parts, cli.Threshold)
	if err != nil {
		slog.Error("Failed to split secret", "err", err)
		kctx.Exit(1)
	}
	slog.Info("Secret split into fragments", "count", len(fragments))

	// --- Encrypt Fragments ---
	encryptedFragments := make(map[string][]byte) // Map: Owner IP -> Encrypted Fragment
	if len(fragments) != len(ownerInfos) {
		// This should not happen if SplitSecret worked correctly
		slog.Error("Internal error: fragment count mismatch", "fragments", len(fragments), "owners", len(ownerInfos))
		kctx.Exit(1)
	}

	for i, ownerInfo := range ownerInfos {
		fragment := fragments[i]
		encrypter := ownerKeys[ownerInfo.IP] // Assumes IP is unique and present
		slog.Debug("Encrypting fragment", "owner_ip", ownerInfo.IP, "fragment_index", i)
		encrypted, err := crypto.EncryptFragment(encrypter, fragment)
		if err != nil {
			slog.Error("Failed to encrypt fragment for owner", "owner_ip", ownerInfo.IP, "err", err)
			kctx.Exit(1)
		}
		encryptedFragments[ownerInfo.IP] = encrypted
		slog.Info("Encrypted fragment", "owner_ip", ownerInfo.IP)
	}

	// --- Construct Entry ---
	entry := &pb.Entry{
		Timestamp:      timestamppb.Now(),
		Key:            cli.Key,
		Readers:        cli.Readers, // Already a slice of strings
		OwnerFragments: encryptedFragments,
		// Signature will be added next
	}
	slog.Debug("Constructed entry structure", "key", entry.Key, "timestamp", entry.Timestamp.AsTime())

	// --- Sign Entry ---
	slog.Debug("Signing entry with master key")
	err = crypto.SignEntry(masterSigner, entry)
	if err != nil {
		slog.Error("Failed to sign entry", "err", err)
		kctx.Exit(1)
	}
	slog.Info("Entry signed successfully")

	// --- Push to Targets ---
	pushRequest := &pb.PushRequest{Entry: entry}
	var wg sync.WaitGroup
	successCount := 0
	errorCount := 0
	var mu sync.Mutex // To protect counters

	for _, target := range cli.Targets {
		wg.Add(1)
		go func(targetEndpoint string) {
			defer wg.Done()
			slog.Info("Connecting to target node", "endpoint", targetEndpoint)
			conn, err := grpc.NewClient(targetEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				slog.Error("Failed to connect to target", "endpoint", targetEndpoint, "err", err)
				mu.Lock()
				errorCount++
				mu.Unlock()
				return
			}
			// defer conn.Close()

			client := pb.NewSssMemVaultClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Add timeout
			defer cancel()

			slog.Info("Pushing entry to target", "endpoint", targetEndpoint, "key", cli.Key)
			_, err = client.Push(ctx, pushRequest)
			if err != nil {
				slog.Error("Failed to push entry to target", "endpoint", targetEndpoint, "key", cli.Key, "err", err)
				mu.Lock()
				errorCount++
				mu.Unlock()
			} else {
				slog.Info("Successfully pushed entry to target", "endpoint", targetEndpoint, "key", cli.Key)
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	slog.Info("Push operation complete", "successful_targets", successCount, "failed_targets", errorCount)

	if errorCount > 0 {
		kctx.Exit(1) // Exit with error if any push failed
	}
	kctx.Exit(0) // Exit successfully
}
