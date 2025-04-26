package crypto

import (
	"bytes"
	"fmt"
	"os"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"
)

// LoadPrivateKey loads a Tink private keyset from a file and returns primitives.
// It assumes the same key is used for signing and hybrid decryption.
func LoadPrivateKey(path string) (tink.Signer, tink.HybridDecrypt, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private keyset file %q: %w", path, err)
	}

	// Using insecurecleartextkeyset assumes the key file itself is protected appropriately.
	// For production, consider using Tink's integration with KMS.
	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private keyset from %q: %w", path, err)
	}

	signer, err := signature.NewSigner(kh)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signer from private keyset %q: %w", path, err)
	}

	decrypt, err := hybrid.NewHybridDecrypt(kh)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hybrid decrypt from private keyset %q: %w", path, err)
	}

	return signer, decrypt, nil
}

// LoadPublicKey loads a Tink public keyset from a file and returns primitives.
// It assumes the same key is used for verification and hybrid encryption.
func LoadPublicKey(path string) (tink.Verifier, tink.HybridEncrypt, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public keyset file %q: %w", path, err)
	}

	// Public keysets are typically safe to read directly.
	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public keyset from %q: %w", path, err)
	}

	verifier, err := signature.NewVerifier(kh)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create verifier from public keyset %q: %w", path, err)
	}

	encrypt, err := hybrid.NewHybridEncrypt(kh)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hybrid encrypt from public keyset %q: %w", path, err)
	}

	return verifier, encrypt, nil
}

// LoadPublicKeyVerifier loads only the verifier primitive from a public keyset file.
func LoadPublicKeyVerifier(path string) (tink.Verifier, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read public keyset from %q: %w", path, err)
	}

	verifier, err := signature.NewVerifier(kh)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier from public keyset %q: %w", path, err)
	}

	return verifier, nil
}

// LoadMasterPrivateKeySigner loads only the signer primitive from a master private keyset file.
func LoadMasterPrivateKeySigner(path string) (tink.Signer, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read master private keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read master private keyset from %q: %w", path, err)
	}

	signer, err := signature.NewSigner(kh)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer from master private keyset %q: %w", path, err)
	}

	return signer, nil
}

// LoadOwnerPublicKeyEncrypter loads only the hybrid encrypter primitive from an owner public keyset file.
func LoadOwnerPublicKeyEncrypter(path string) (tink.HybridEncrypt, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read owner public keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read owner public keyset from %q: %w", path, err)
	}

	encrypt, err := hybrid.NewHybridEncrypt(kh)
	if err != nil {
		return nil, fmt.Errorf("failed to create hybrid encrypt from owner public keyset %q: %w", path, err)
	}

	return encrypt, nil
}
