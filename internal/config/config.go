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
	Endpoint      string         `yaml:"endpoint"`                // e.g., "node1.example.com:59240" or "192.168.1.101:59240"
	PublicKeyPath string         `yaml:"public_key_path"`         // Path to peer's combined public keyset file (signing + hybrid)
	PollInterval  *time.Duration `yaml:"poll_interval,omitempty"` // Optional polling frequency (Go duration string)
	// FragmentsPerOwner specifies how many SSS fragments this peer should own for secrets it's an owner of. Defaults to 1.
	FragmentsPerOwner int `yaml:"fragments_per_owner,omitempty"`

	// Internal fields populated after loading
	PubKeyVerifier  tink.Verifier      `yaml:"-"` // Tink public key verifier (from public_key_path)
	PubKeyEncrypter tink.HybridEncrypt `yaml:"-"` // Tink public key encrypter (from public_key_path)
}

// Config holds the application's configuration.
type Config struct {
	PrivateKeyPath      string                `yaml:"private_key_path"`       // Path to this node's combined private keyset file (signing + hybrid)
	MasterPublicKeyPath string                `yaml:"master_public_key_path"` // Path to master public key file (signing only) for verifying entry signatures
	ListenAddress       string                `yaml:"listen_address"`         // e.g., ":59240"
	Peers               map[string]PeerConfig `yaml:"peers"`                  // Map: Peer Name -> PeerConfig
	MaxTimestampSkew    time.Duration         `yaml:"max_timestamp_skew"`     // e.g., 30s

	// Internal fields populated after loading
	PrivKeySigner    tink.Signer            `yaml:"-"` // Tink private key signer (from private_key_path)
	PrivKeyDecrypter tink.HybridDecrypt     `yaml:"-"` // Tink private key decrypter (from private_key_path)
	MasterPubKey     tink.Verifier          `yaml:"-"` // Tink master public key verifier (from master_public_key_path)
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
		if cfg.PrivateKeyPath == "" {
			return nil, errors.New("config validation failed: private_key_path is required")
		}
	}
	if cfg.MasterPublicKeyPath == "" {
		return nil, errors.New("config validation failed: master_public_key_path is required")
	}
	if cfg.MaxTimestampSkew <= 0 {
		return nil, errors.New("config validation failed: max_timestamp_skew must be positive")
	}

	// --- Load Own Keys (Signer and Decrypter from the same file) ---
	err = loadOwnPrivateKeys(&cfg, ignoreOwnKeyErrors)
	if err != nil {
		return nil, err // Error already contains context
	}

	// --- Load Master Key (Verifier only) ---
	cfg.MasterPubKey, err = crypto.LoadVerifier(cfg.MasterPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load master public key verifier: %w", err)
	}
	slog.Info("Loaded master public key verifier", "path", cfg.MasterPublicKeyPath)

	// --- Load Peer Keys (Verifier and Encrypter from the same file) ---
	loadedPeers := maps.Clone(cfg.Peers)
	if loadedPeers == nil {
		loadedPeers = make(map[string]PeerConfig)
	}
	cfg.LoadedPeers = make(map[string]*PeerConfig, len(loadedPeers)) // Initialize the final map

	for name, peerCfg := range loadedPeers { // Iterate over the cloned map
		if name == "" {
			return nil, errors.New("config validation failed: peer name cannot be empty")
		}
		if peerCfg.PublicKeyPath == "" {
			return nil, fmt.Errorf("config validation failed: public_key_path is required for peer %q", name)
		}
		if peerCfg.Endpoint == "" {
			slog.Debug("Peer config has empty endpoint, assuming client-only entry", "peer_name", name)
		}
		// Set default FragmentsPerOwner if not specified
		if peerCfg.FragmentsPerOwner <= 0 {
			peerCfg.FragmentsPerOwner = 1
			slog.Debug("Setting default fragments_per_owner=1 for peer", "peer_name", name)
		}

		// Load Public Key Verifier
		verifier, err := crypto.LoadVerifier(peerCfg.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key verifier for peer %q from %q: %w", name, peerCfg.PublicKeyPath, err)
		}
		slog.Info("Loaded peer public key verifier", "peer_name", name, "path", peerCfg.PublicKeyPath)

		// Load Public Key Encrypter
		encrypter, err := crypto.LoadEncrypter(peerCfg.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key encrypter for peer %q from %q: %w", name, peerCfg.PublicKeyPath, err)
		}
		slog.Info("Loaded peer public key encrypter", "peer_name", name, "path", peerCfg.PublicKeyPath)

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

// loadOwnPrivateKeys loads the signer and decrypter from the configured private key path.
// It modifies the cfg object directly.
func loadOwnPrivateKeys(cfg *Config, ignoreOwnKeyErrors bool) error {
	if cfg.PrivateKeyPath == "" {
		if !ignoreOwnKeyErrors {
			// This case is caught by the validation check in loadConfigInternal,
			// but checking here makes this function self-contained.
			return errors.New("config validation failed: private_key_path is required")
		}
		slog.Debug("Own private_key_path not specified, skipping loading.")
		return nil // Not an error if ignoring is allowed
	}

	var err error

	// Load Signer
	cfg.PrivKeySigner, err = crypto.LoadSigner(cfg.PrivateKeyPath)
	if err != nil {
		if ignoreOwnKeyErrors {
			slog.Warn("Ignoring error while loading own signer from private keyset", "path", cfg.PrivateKeyPath, "err", err)
			cfg.PrivKeySigner = nil // Ensure it's nil if loading failed
		} else {
			return fmt.Errorf("failed to load own signer from private keyset %q: %w", cfg.PrivateKeyPath, err)
		}
	} else {
		slog.Info("Loaded own signer from private keyset", "path", cfg.PrivateKeyPath)
	}

	// Load Decrypter
	cfg.PrivKeyDecrypter, err = crypto.LoadDecrypter(cfg.PrivateKeyPath)
	if err != nil {
		if ignoreOwnKeyErrors {
			slog.Warn("Ignoring error while loading own decrypter from private keyset", "path", cfg.PrivateKeyPath, "err", err)
			cfg.PrivKeyDecrypter = nil // Ensure it's nil if loading failed
		} else {
			// Even if signer loaded successfully, return error if decrypter fails (unless ignoring)
			return fmt.Errorf("failed to load own decrypter from private keyset %q: %w", cfg.PrivateKeyPath, err)
		}
	} else {
		slog.Info("Loaded own decrypter from private keyset", "path", cfg.PrivateKeyPath)
	}

	return nil // Success (or ignored errors)
}
