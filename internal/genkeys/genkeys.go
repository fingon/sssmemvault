package genkeys

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"

	// Register Tink primitives via blank imports for side effects.
	_ "github.com/tink-crypto/tink-go/v2/aead" // Needed for AEAD dependency in hybrid
	"github.com/tink-crypto/tink-go/v2/hybrid"
	_ "github.com/tink-crypto/tink-go/v2/hybrid" // Register HybridEncrypt/Decrypt key managers
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	// tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto" // Unused
	"github.com/tink-crypto/tink-go/v2/signature"
	_ "github.com/tink-crypto/tink-go/v2/signature" // Register Signature key managers
)

// Config holds the specific configuration needed for the genkeys subcommand.
type Config struct {
	PrivateKeyOut string `kong:"name='private-out',required,help='Path to write the combined private keyset file (JSON).'"`
	PublicKeyOut  string `kong:"name='public-out',required,help='Path to write the combined public keyset file (JSON).'"`
	Force         bool   `kong:"name='force',short='f',help='Overwrite existing key files.'"`
	// LogLevel is handled globally
}

// FileExists checks if a file exists and is not a directory.
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// generateAndCombineKeys generates signing and hybrid keys and combines them into single handles.
func generateAndCombineKeys() (*keyset.Handle, error) {
	// 1. Define Key Templates
	signingTemplate := signature.ECDSAP256KeyTemplate() // Or ED25519KeyTemplate()
	hybridTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template()

	// 2. Initialize Keyset Manager
	manager := keyset.NewManager()

	// 3. Add Keys to Manager
	// Add signing key
	managerSigningKeyID, err := manager.Add(signingTemplate) // Add returns keyID, err
	if err != nil {
		return nil, fmt.Errorf("failed to add signing key template to manager: %w", err)
	}
	err = manager.SetPrimary(managerSigningKeyID) // Set signing key as primary
	if err != nil {
		return nil, fmt.Errorf("failed to set signing key as primary: %w", err)
	}
	slog.Debug("Added signing key to manager", "key_id", managerSigningKeyID)

	// Add hybrid key
	managerHybridKeyID, err := manager.Add(hybridTemplate) // Add returns keyID, err
	if err != nil {
		return nil, fmt.Errorf("failed to add hybrid key template to manager: %w", err)
	}
	slog.Debug("Added hybrid key to manager", "key_id", managerHybridKeyID)

	// Signing key remains primary as set above.

	// Get the final combined handle
	combinedHandle, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get final combined handle from manager: %w", err)
	}

	slog.Debug("Successfully combined keys into one handle", "primary_key_id", combinedHandle.KeysetInfo().PrimaryKeyId)
	return combinedHandle, nil
}

// WriteKeyset writes a keyset handle to a file using JSON format.
func WriteKeyset(handle *keyset.Handle, path string) error {
	buf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(buf)
	// Use insecurecleartextkeyset for writing private keys (and public for consistency)
	err := insecurecleartextkeyset.Write(handle, writer)
	if err != nil {
		return fmt.Errorf("failed to write keyset to buffer for %q: %w", path, err)
	}
	err = os.WriteFile(path, buf.Bytes(), 0o600) // Restrictive permissions
	if err != nil {
		return fmt.Errorf("failed to save keyset file %q: %w", path, err)
	}
	slog.Info("Keyset written successfully", "path", path)
	return nil
}

// Run executes the genkeys operation.
func (cfg *Config) Run() error {
	slog.Info("Starting key generation...")

	// --- Check if files exist ---
	if !cfg.Force {
		if FileExists(cfg.PrivateKeyOut) {
			slog.Error("Private key output file already exists. Use --force to overwrite.", "path", cfg.PrivateKeyOut)
			return errors.New("already-exists")
		}
		if FileExists(cfg.PublicKeyOut) {
			slog.Error("Public key output file already exists. Use --force to overwrite.", "path", cfg.PublicKeyOut)
			return errors.New("already-exists")
		}
	}

	// --- Generate Combined Private Keyset Handle ---
	privateHandle, err := generateAndCombineKeys()
	if err != nil {
		return err
	}

	// --- Extract Public Keyset Handle ---
	publicHandle, err := privateHandle.Public()
	if err != nil {
		return err
	}

	// --- Write Private Keyset ---
	err = WriteKeyset(privateHandle, cfg.PrivateKeyOut)
	if err != nil {
		slog.Error("Failed to write private keyset", "path", cfg.PrivateKeyOut, "err", err)
		// Attempt to clean up public key file if private write failed
		_ = os.Remove(cfg.PublicKeyOut)
		return err
	}

	// --- Write Public Keyset ---
	err = WriteKeyset(publicHandle, cfg.PublicKeyOut)
	if err != nil {
		slog.Error("Failed to write public keyset", "path", cfg.PublicKeyOut, "err", err)
		// Clean up private key file as the process was not fully successful
		_ = os.Remove(cfg.PrivateKeyOut)
		return err
	}

	slog.Info("Key generation completed successfully.")
	return nil
}
