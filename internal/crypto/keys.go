package crypto

import (
	"bytes"
	"fmt"
	"os"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// --- Private Key Loading ---

// LoadPrivateKeySigner loads only the signer primitive from a private keyset file.
// Expects a keyset containing signing keys (e.g., ECDSA, ED25519).
func LoadPrivateKeySigner(path string) (tink.Signer, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing private keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read signing private keyset from %q: %w", path, err)
	}

	signer, err := signature.NewSigner(kh)
	if err != nil {
		// Check if the keyset might be missing a signing key or is the wrong type
		_, verifyErr := signature.NewVerifier(kh)
		if verifyErr == nil {
			// It has a verification key, but not a signing key. Wrong key type loaded.
			return nil, fmt.Errorf("keyset in %q contains a public verification key, but a private signing key is required: %w", path, err)
		}
		// Check if it's a hybrid key
		_, hybridErr := hybrid.NewHybridDecrypt(kh)
		if hybridErr == nil {
			return nil, fmt.Errorf("keyset in %q contains a hybrid decryption key, but a private signing key is required: %w", path, err)
		}
		return nil, fmt.Errorf("failed to create signer from private keyset %q (ensure it contains signing keys): %w", path, err)
	}

	return signer, nil
}

// LoadPrivateKeyDecrypter loads only the hybrid decrypt primitive from a private keyset file.
// Expects a keyset containing hybrid decryption keys (e.g., DHKEM).
func LoadPrivateKeyDecrypter(path string) (tink.HybridDecrypt, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read hybrid private keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read hybrid private keyset from %q: %w", path, err)
	}

	decrypt, err := hybrid.NewHybridDecrypt(kh)
	if err != nil {
		// Check if it's a signing key
		_, signErr := signature.NewSigner(kh)
		if signErr == nil {
			return nil, fmt.Errorf("keyset in %q contains a private signing key, but a hybrid decryption key is required: %w", path, err)
		}
		return nil, fmt.Errorf("failed to create hybrid decrypt from private keyset %q (ensure it contains hybrid keys): %w", path, err)
	}

	return decrypt, nil
}

// --- Public Key Loading ---

// LoadPublicKeyVerifier loads only the verifier primitive from a public keyset file.
// Expects a keyset containing public verification keys (e.g., ECDSA, ED25519).
func LoadPublicKeyVerifier(path string) (tink.Verifier, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read signing public keyset from %q: %w", path, err)
	}

	verifier, err := signature.NewVerifier(kh)
	if err != nil {
		// Check if it's a hybrid key
		_, hybridErr := hybrid.NewHybridEncrypt(kh)
		if hybridErr == nil {
			return nil, fmt.Errorf("keyset in %q contains a public hybrid encryption key, but a public verification key is required: %w", path, err)
		}
		return nil, fmt.Errorf("failed to create verifier from public keyset %q (ensure it contains verification keys): %w", path, err)
	}

	return verifier, nil
}

// LoadPublicKeyEncrypter loads only the hybrid encrypter primitive from a public keyset file.
// Expects a keyset containing public hybrid encryption keys (e.g., DHKEM).
func LoadPublicKeyEncrypter(path string) (tink.HybridEncrypt, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read hybrid public keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read hybrid public keyset from %q: %w", path, err)
	}

	encrypt, err := hybrid.NewHybridEncrypt(kh)
	if err != nil {
		// Check if it's a verification key
		_, verifyErr := signature.NewVerifier(kh)
		if verifyErr == nil {
			return nil, fmt.Errorf("keyset in %q contains a public verification key, but a public hybrid encryption key is required: %w", path, err)
		}
		return nil, fmt.Errorf("failed to create hybrid encrypt from public keyset %q (ensure it contains hybrid keys): %w", path, err)
	}

	return encrypt, nil
}

// LoadMasterPrivateKeySigner is an alias for LoadPrivateKeySigner, emphasizing its use case.
// Expects a keyset containing signing keys.
func LoadMasterPrivateKeySigner(path string) (tink.Signer, error) {
	return LoadPrivateKeySigner(path)
}

// LoadOwnerPublicKeyEncrypter is an alias for LoadPublicKeyEncrypter, emphasizing its use case.
// Expects a keyset containing public hybrid encryption keys.
func LoadOwnerPublicKeyEncrypter(path string) (tink.HybridEncrypt, error) {
	return LoadPublicKeyEncrypter(path)
}

// LoadClientHybridPrivateKey loads the hybrid decrypt primitive from a private keyset file,
// specifically for the client 'get' operation.
// Expects a keyset containing hybrid decryption keys.
func LoadClientHybridPrivateKey(path string) (tink.HybridDecrypt, error) {
	return LoadPrivateKeyDecrypter(path)
}
