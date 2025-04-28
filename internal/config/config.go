package config

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"time"

	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"gopkg.in/yaml.v3"
)

const (
	DefaultListenAddress    = ":59240"
	DefaultMaxTimestampSkew = 30 * time.Second
)

// PeerConfig holds configuration for a single peer node.
type PeerConfig struct {
	Endpoint         string         `yaml:"endpoint"`                // e.g., "node1.example.com:59240" or "192.168.1.101:59240"
	SigningPublicKey string         `yaml:"signing_public_key"`      // Path to peer's public key file for signature verification
	HybridPublicKey  string         `yaml:"hybrid_public_key"`       // Path to peer's public key file for hybrid encryption
	PollInterval     *time.Duration `yaml:"poll_interval,omitempty"` // Optional polling frequency (Go duration string)
	// AllowedSourceCIDRs removed as auth is now name-based

	// Internal fields populated after loading
	PubKeyVerifier  tink.Verifier      `yaml:"-"` // Tink public key verifier (from signing_public_key)
	PubKeyEncrypter tink.HybridEncrypt `yaml:"-"` // Tink public key encrypter (from hybrid_public_key)
}

// Config holds the application's configuration.
type Config struct {
	SigningPrivateKeyPath  string                `yaml:"signing_private_key_path"`  // Path to this node's private key file for signing requests
	HybridPrivateKeyPath   string                `yaml:"hybrid_private_key_path"`   // Path to this node's private key file for decrypting fragments
	MasterSigningPublicKey string                `yaml:"master_signing_public_key"` // Path to master public key file for verifying entry signatures
	ListenAddress          string                `yaml:"listen_address"`            // e.g., ":59240"
	Peers                  map[string]PeerConfig `yaml:"peers"`                     // Map: Peer Name -> PeerConfig
	MaxTimestampSkew       time.Duration         `yaml:"max_timestamp_skew"`        // e.g., 30s

	// Internal fields populated after loading
	PrivKeySigner    tink.Signer            `yaml:"-"` // Tink private key signer (from signing_private_key_path)
	PrivKeyDecrypter tink.HybridDecrypt     `yaml:"-"` // Tink private key decrypter (from hybrid_private_key_path)
	MasterPubKey     tink.Verifier          `yaml:"-"` // Tink master public key verifier (from master_signing_public_key)
	LoadedPeers      map[string]*PeerConfig `yaml:"-"` // Processed peers with loaded keys (map key is Name)
}

// loadConfigInternal performs the core logic of reading, unmarshalling, validating,
// and loading keys from a configuration file.
func loadConfigInternal(path string, ignoreOwnKeyErrors bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	cfg := Config{
		ListenAddress:    DefaultListenAddress,
		MaxTimestampSkew: DefaultMaxTimestampSkew,
		LoadedPeers:      make(map[string]*PeerConfig),
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file %q: %w", path, err)
	}

	// --- Validation ---
	if !ignoreOwnKeyErrors {
		if cfg.SigningPrivateKeyPath == "" {
			return nil, errors.New("config validation failed: signing_private_key_path is required")
		}
		if cfg.HybridPrivateKeyPath == "" {
			return nil, errors.New("config validation failed: hybrid_private_key_path is required")
		}
	}
	if cfg.MasterSigningPublicKey == "" {
		return nil, errors.New("config validation failed: master_signing_public_key is required")
	}
	if cfg.MaxTimestampSkew <= 0 {
		return nil, errors.New("config validation failed: max_timestamp_skew must be positive")
	}

	// --- Load Own Keys ---
	if cfg.SigningPrivateKeyPath != "" {
		cfg.PrivKeySigner, err = crypto.LoadPrivateKeySigner(cfg.SigningPrivateKeyPath)
		if err != nil {
			if ignoreOwnKeyErrors {
				slog.Warn("Ignoring error while loading own signing private key specified in config", "path", cfg.SigningPrivateKeyPath, "err", err)
				cfg.PrivKeySigner = nil // Ensure it's nil if loading failed
			} else {
				return nil, fmt.Errorf("failed to load own signing private key: %w", err)
			}
		} else {
			slog.Info("Loaded own signing private key", "path", cfg.SigningPrivateKeyPath)
		}
	} else if !ignoreOwnKeyErrors {
		// If we require own keys and the path is empty, it's an error (caught by validation above)
		// If we ignore errors, log that it wasn't specified.
		slog.Debug("Own signing_private_key_path not specified in config.")
	}

	if cfg.HybridPrivateKeyPath != "" {
		cfg.PrivKeyDecrypter, err = crypto.LoadPrivateKeyDecrypter(cfg.HybridPrivateKeyPath)
		if err != nil {
			if ignoreOwnKeyErrors {
				slog.Warn("Ignoring error while loading own hybrid private key specified in config", "path", cfg.HybridPrivateKeyPath, "err", err)
				cfg.PrivKeyDecrypter = nil // Ensure it's nil if loading failed
			} else {
				return nil, fmt.Errorf("failed to load own hybrid private key: %w", err)
			}
		} else {
			slog.Info("Loaded own hybrid private key", "path", cfg.HybridPrivateKeyPath)
		}
	} else if !ignoreOwnKeyErrors {
		// If we require own keys and the path is empty, it's an error (caught by validation above)
		// If we ignore errors, log that it wasn't specified.
		slog.Debug("Own hybrid_private_key_path not specified in config.")
	}

	// --- Load Master Key ---
	cfg.MasterPubKey, err = crypto.LoadPublicKeyVerifier(cfg.MasterSigningPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load master signing public key: %w", err)
	}
	slog.Info("Loaded master signing public key", "path", cfg.MasterSigningPublicKey)

	// --- Load Peer Keys ---
	loadedPeers := maps.Clone(cfg.Peers)
	if loadedPeers == nil {
		loadedPeers = make(map[string]PeerConfig)
	}
	cfg.LoadedPeers = make(map[string]*PeerConfig, len(loadedPeers)) // Initialize the final map

	for name, peerCfg := range loadedPeers { // Iterate over the cloned map
		if name == "" {
			return nil, errors.New("config validation failed: peer name cannot be empty")
		}
		if peerCfg.SigningPublicKey == "" {
			return nil, fmt.Errorf("config validation failed: signing_public_key is required for peer %q", name)
		}
		if peerCfg.HybridPublicKey == "" {
			return nil, fmt.Errorf("config validation failed: hybrid_public_key is required for peer %q", name)
		}
		if peerCfg.Endpoint == "" {
			slog.Debug("Peer config has empty endpoint, assuming client-only entry", "peer_name", name)
		}

		// Load Signing Public Key (Verifier)
		verifier, err := crypto.LoadPublicKeyVerifier(peerCfg.SigningPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load signing public key for peer %q: %w", name, err)
		}
		slog.Info("Loaded peer signing public key", "peer_name", name, "path", peerCfg.SigningPublicKey)

		// Load Hybrid Public Key (Encrypter)
		encrypter, err := crypto.LoadPublicKeyEncrypter(peerCfg.HybridPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load hybrid public key for peer %q: %w", name, err)
		}
		slog.Info("Loaded peer hybrid public key", "peer_name", name, "path", peerCfg.HybridPublicKey)

		// Store the loaded keys and the config struct pointer in the final map
		loadedPeer := peerCfg // Create a copy of the struct from the iteration
		loadedPeer.PubKeyVerifier = verifier
		loadedPeer.PubKeyEncrypter = encrypter
		cfg.LoadedPeers[name] = &loadedPeer // Store pointer to the copy
	}

	logMsg := "Configuration loaded successfully"
	if ignoreOwnKeyErrors {
		logMsg += " (ignoring own private key errors)"
	}
	slog.Info(logMsg)
	return &cfg, nil
}

// LoadConfig reads the configuration file, validates it, and loads keys.
func LoadConfig(path string) (*Config, error) {
	return loadConfigInternal(path, false)
}

// LoadConfigIgnoreOwnKey reads the configuration file, validates it, and loads keys,
// but specifically ignores errors related to loading the node's own private key.
// Useful for client tools (like push or get) that use a different key for their operations.
func LoadConfigIgnoreOwnKey(path string) (*Config, error) {
	return loadConfigInternal(path, true)
}
