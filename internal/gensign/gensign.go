package gensign

import (
	"errors"
	"log/slog"
	"os"

	"github.com/fingon/sssmemvault/internal/genkeys"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
)

type Config struct {
	Force         bool   `kong:"name='force',short='f',help='Overwrite existing key files.'"`
	Prefix        string `kong:"name='prefix',help='Prefix for generating private and public key files.'"`
	PrivateKeyOut string `kong:"name='private-out',help='Path to write the signing private keyset file (JSON).'"`
	PublicKeyOut  string `kong:"name='public-out',help='Path to write the signing public keyset file (JSON).'"`
}

func (cfg *Config) Run() error {
	slog.Info("Starting key generation...")

	if cfg.Prefix != "" {
		cfg.PrivateKeyOut = cfg.Prefix + "_private.json"
		cfg.PublicKeyOut = cfg.Prefix + "_public.json"
	}

	if !cfg.Force {
		if genkeys.FileExists(cfg.PrivateKeyOut) {
			slog.Error("Private key output file already exists. Use --force to overwrite.", "path", cfg.PrivateKeyOut)
			return errors.New("already-exists")
		}
		if genkeys.FileExists(cfg.PublicKeyOut) {
			slog.Error("Public key output file already exists. Use --force to overwrite.", "path", cfg.PublicKeyOut)
			return errors.New("already-exists")
		}
	}

	handle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		return err
	}

	publicHandle, err := handle.Public()
	if err != nil {
		return err
	}

	err = genkeys.WriteKeyset(handle, cfg.PrivateKeyOut)
	if err != nil {
		slog.Error("Failed to write private keyset", "path", cfg.PrivateKeyOut, "err", err)
		// Attempt to clean up public key file if private write failed
		_ = os.Remove(cfg.PublicKeyOut)
		return err
	}

	err = genkeys.WriteKeyset(publicHandle, cfg.PublicKeyOut)
	if err != nil {
		slog.Error("Failed to write public keyset", "path", cfg.PublicKeyOut, "err", err)
		// Clean up private key file as the process was not fully successful
		_ = os.Remove(cfg.PrivateKeyOut)
		return err
	}

	slog.Info("Key generation completed successfully.")
	return nil
}
