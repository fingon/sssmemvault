package config

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"time"

	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/google/tink/go/tink"
	"gopkg.in/yaml.v3"
)

const (
	DefaultListenAddress    = ":59240"
	DefaultMaxTimestampSkew = 30 * time.Second
)

// PeerConfig holds configuration for a single peer node.
type PeerConfig struct {
	Endpoint     string         `yaml:"endpoint"`                // e.g., "192.168.1.101:59240"
	PublicKey    string         `yaml:"public_key"`              // Path to peer's public key file
	PollInterval *time.Duration `yaml:"poll_interval,omitempty"` // Optional polling frequency (Go duration string)
	// Optional: List of CIDRs allowed to connect using this peer's key. e.g., ["192.168.1.101/32", "2001:db8::/64"]
	AllowedSourceCIDRs []string `yaml:"allowed_source_cidrs,omitempty"`

	// Internal fields populated after loading
	PubKeyVerifier  tink.Verifier      `yaml:"-"` // Tink public key verifier
	PubKeyEncrypter tink.HybridEncrypt `yaml:"-"` // Tink public key encrypter (needed for provisioning tool, maybe not server)
}

// Config holds the application's configuration.
type Config struct {
	PrivateKeyPath   string                `yaml:"private_key_path"`   // Path to this node's private key file
	MasterPublicKey  string                `yaml:"master_public_key"`  // Path to master public key file
	ListenAddress    string                `yaml:"listen_address"`     // e.g., ":59240"
	Peers            map[string]PeerConfig `yaml:"peers"`              // Map: Peer IP -> PeerConfig
	MaxTimestampSkew time.Duration         `yaml:"max_timestamp_skew"` // e.g., 30s
	// MyIP             string                `yaml:"my_ip"` // Removed: Provided via CLI flag now

	// Internal fields populated after loading
	PrivKeySigner    tink.Signer            `yaml:"-"` // Tink private key signer
	PrivKeyDecrypter tink.HybridDecrypt     `yaml:"-"` // Tink private key decrypter
	MasterPubKey     tink.Verifier          `yaml:"-"` // Tink master public key verifier
	LoadedPeers      map[string]*PeerConfig `yaml:"-"` // Processed peers with loaded keys (map key is IP)
}

// LoadConfig reads the configuration file, validates it, and loads keys.
func LoadConfig(path string) (*Config, error) {
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
	if cfg.PrivateKeyPath == "" {
		return nil, errors.New("config validation failed: private_key_path is required")
	}
	if cfg.MasterPublicKey == "" {
		return nil, errors.New("config validation failed: master_public_key is required")
	}
	// my_ip validation removed, provided via CLI flag
	if cfg.MaxTimestampSkew <= 0 {
		return nil, errors.New("config validation failed: max_timestamp_skew must be positive")
	}

	// --- Load Keys ---
	cfg.PrivKeySigner, cfg.PrivKeyDecrypter, err = crypto.LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load own private key: %w", err)
	}
	slog.Info("Loaded own private key", "path", cfg.PrivateKeyPath)

	cfg.MasterPubKey, err = crypto.LoadPublicKeyVerifier(cfg.MasterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load master public key: %w", err)
	}
	slog.Info("Loaded master public key", "path", cfg.MasterPublicKey)

	// --- Load Peer Keys ---
	// Create a mutable copy to store loaded keys back into
	loadedPeers := maps.Clone(cfg.Peers) // Requires Go 1.21+
	if loadedPeers == nil {
		loadedPeers = make(map[string]PeerConfig) // For older Go versions or if Peers was nil
	}

	for ip, peerCfg := range cfg.Peers {
		if peerCfg.PublicKey == "" {
			return nil, fmt.Errorf("config validation failed: public_key is required for peer %q", ip)
		}
		if peerCfg.Endpoint == "" {
			return nil, fmt.Errorf("config validation failed: endpoint is required for peer %q", ip)
		}

		verifier, encrypter, err := crypto.LoadPublicKey(peerCfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key for peer %q: %w", ip, err)
		}

		// Store the loaded keys back into the temporary map
		loadedPeer := loadedPeers[ip] // Get the struct copy from the cloned map
		loadedPeer.PubKeyVerifier = verifier
		loadedPeer.PubKeyEncrypter = encrypter
		loadedPeers[ip] = loadedPeer // Put the updated struct back

		slog.Info("Loaded peer public key", "peer_ip", ip, "path", peerCfg.PublicKey)
	}
	// Assign the map with loaded keys back to the config
	cfg.LoadedPeers = make(map[string]*PeerConfig, len(loadedPeers))
	for ip, peer := range loadedPeers {
		p := peer // Create a new variable p that is a copy of peer for this iteration
		cfg.LoadedPeers[ip] = &p
	}

	slog.Info("Configuration loaded successfully")
	return &cfg, nil
}

// LoadConfigIgnoreOwnKey reads the configuration file, validates it, and loads keys,
// but specifically ignores errors related to loading the node's own private key.
// Useful for client tools (like push or get) that use a different key for their operations.
func LoadConfigIgnoreOwnKey(path string) (*Config, error) {
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
	// Skip private_key_path validation
	if cfg.MasterPublicKey == "" {
		return nil, errors.New("config validation failed: master_public_key is required")
	}
	if cfg.MaxTimestampSkew <= 0 {
		return nil, errors.New("config validation failed: max_timestamp_skew must be positive")
	}

	// --- Load Keys (Ignoring Own Private Key) ---
	// Attempt to load own private key, but log warning instead of failing on error
	if cfg.PrivateKeyPath != "" {
		_, _, err = crypto.LoadPrivateKey(cfg.PrivateKeyPath)
		if err != nil {
			slog.Warn("Ignoring error while loading own private key specified in config", "path", cfg.PrivateKeyPath, "err", err)
			// Clear the potentially loaded (but maybe partial) keys if error occurred
			cfg.PrivKeySigner = nil
			cfg.PrivKeyDecrypter = nil
		} else {
			slog.Debug("Loaded own private key specified in config (likely unused by client)", "path", cfg.PrivateKeyPath)
		}
	} else {
		slog.Debug("Own private_key_path not specified in config, skipping load.")
	}

	cfg.MasterPubKey, err = crypto.LoadPublicKeyVerifier(cfg.MasterPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load master public key: %w", err)
	}
	slog.Info("Loaded master public key", "path", cfg.MasterPublicKey)

	// --- Load Peer Keys ---
	loadedPeers := maps.Clone(cfg.Peers)
	if loadedPeers == nil {
		loadedPeers = make(map[string]PeerConfig)
	}

	for ip, peerCfg := range cfg.Peers {
		if peerCfg.PublicKey == "" {
			return nil, fmt.Errorf("config validation failed: public_key is required for peer %q", ip)
		}
		if peerCfg.Endpoint == "" {
			return nil, fmt.Errorf("config validation failed: endpoint is required for peer %q", ip)
		}

		verifier, encrypter, err := crypto.LoadPublicKey(peerCfg.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key for peer %q: %w", ip, err)
		}

		loadedPeer := loadedPeers[ip]
		loadedPeer.PubKeyVerifier = verifier
		loadedPeer.PubKeyEncrypter = encrypter
		loadedPeers[ip] = loadedPeer

		slog.Info("Loaded peer public key", "peer_ip", ip, "path", peerCfg.PublicKey)
	}

	cfg.LoadedPeers = make(map[string]*PeerConfig, len(loadedPeers))
	for ip, peer := range loadedPeers {
		p := peer
		cfg.LoadedPeers[ip] = &p
	}

	slog.Info("Configuration loaded successfully (ignoring own private key errors)")
	return &cfg, nil
}
