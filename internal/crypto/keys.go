package crypto

import (
	"bytes"
	"fmt"
	"os"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// --- Keyset Loading ---

// loadKeysetHandle reads a JSON keyset file (potentially containing multiple keys)
// and returns a keyset handle. It uses insecurecleartextkeyset as keys are stored
// unencrypted locally.
func loadKeysetHandle(path string) (*keyset.Handle, error) {
	jsonKeyset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset file %q: %w", path, err)
	}

	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(jsonKeyset)))
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset from %q: %w", path, err)
	}

	return kh, nil
}

// --- Primitive Loading from Keyset Files ---

// LoadSigner loads the Signer primitive from a keyset file.
// It expects the primary key in the keyset to be a signing key.
func LoadSigner(path string) (tink.Signer, error) {
	kh, err := loadKeysetHandle(path)
	if err != nil {
		return nil, err // Error already contains path context
	}
	// Get the primitive set associated with the handle
	ps, err := kh.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from keyset %q: %w", path, err)
	}
	// Check if the primary primitive is a Signer
	signer, ok := ps.Primary.Primitive.(tink.Signer)
	if !ok {
		return nil, fmt.Errorf("primary primitive in keyset %q is not a tink.Signer", path)
	}
	return signer, nil
}

// LoadDecrypter loads the HybridDecrypt primitive from a keyset file.
// It searches for the first available hybrid decryption key in the keyset.
func LoadDecrypter(path string) (tink.HybridDecrypt, error) {
	kh, err := loadKeysetHandle(path)
	if err != nil {
		return nil, err // Error already contains path context
	}
	// Get the primitive set associated with the handle
	ps, err := kh.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from keyset %q: %w", path, err)
	}
	// Iterate through all primitives to find a HybridDecrypt primitive
	for _, entryList := range ps.Entries { // Iterate through entries for each status (ENABLED, etc.)
		for _, entry := range entryList {
			if decrypter, ok := entry.Primitive.(tink.HybridDecrypt); ok {
				// Found a hybrid decrypter, return it.
				return decrypter, nil
			}
		}
	}
	return nil, fmt.Errorf("no tink.HybridDecrypt primitive found in keyset %q", path)
}

// LoadVerifier loads the Verifier primitive from a keyset file.
// It expects the primary key in the keyset to be a verification key.
func LoadVerifier(path string) (tink.Verifier, error) {
	kh, err := loadKeysetHandle(path)
	if err != nil {
		return nil, err // Error already contains path context
	}
	// Get the primitive set associated with the handle
	ps, err := kh.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from keyset %q: %w", path, err)
	}
	// Check if the primary primitive is a Verifier
	verifier, ok := ps.Primary.Primitive.(tink.Verifier)
	if !ok {
		return nil, fmt.Errorf("primary primitive in keyset %q is not a tink.Verifier", path)
	}
	return verifier, nil
}

// LoadEncrypter loads the HybridEncrypt primitive from a keyset file.
// It searches for the first available hybrid encryption key in the keyset.
func LoadEncrypter(path string) (tink.HybridEncrypt, error) {
	kh, err := loadKeysetHandle(path)
	if err != nil {
		return nil, err // Error already contains path context
	}
	// Get the primitive set associated with the handle
	ps, err := kh.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from keyset %q: %w", path, err)
	}
	// Iterate through all primitives to find a HybridEncrypt primitive
	for _, entryList := range ps.Entries { // Iterate through entries for each status (ENABLED, etc.)
		for _, entry := range entryList {
			if encrypter, ok := entry.Primitive.(tink.HybridEncrypt); ok {
				// Found a hybrid encrypter, return it.
				return encrypter, nil
			}
		}
	}
	return nil, fmt.Errorf("no tink.HybridEncrypt primitive found in keyset %q", path)
}
