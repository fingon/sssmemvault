package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/tink-crypto/tink-go/v2/core/primitiveset"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// --- Keyset Loading ---

// loadKeysetHandle reads a JSON keyset file and returns a keyset handle.
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

// loadKeysetHandleFromValue reads a JSON keyset string and returns a keyset handle.
func loadKeysetHandleFromValue(jsonKeyset string) (*keyset.Handle, error) {
	kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader([]byte(jsonKeyset))))
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset from value: %w", err)
	}
	return kh, nil
}

// getPrimitivesFromKeysetFile loads a keyset handle from a file and returns its PrimitiveSet.
// This helper centralizes the initial steps common to loading specific primitives.
func getPrimitivesFromKeysetFile(path string) (*primitiveset.PrimitiveSet, error) {
	kh, err := loadKeysetHandle(path)
	if err != nil {
		return nil, err // Error already contains path context from loadKeysetHandle
	}
	ps, err := kh.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from keyset %q: %w", path, err)
	}
	return ps, nil
}

// getPrimitivesFromKeysetValue loads a keyset handle from a string value and returns its PrimitiveSet.
func getPrimitivesFromKeysetValue(jsonKeyset string) (*primitiveset.PrimitiveSet, error) {
	kh, err := loadKeysetHandleFromValue(jsonKeyset)
	if err != nil {
		return nil, err
	}
	ps, err := kh.Primitives()
	if err != nil {
		return nil, fmt.Errorf("failed to get primitives from keyset value: %w", err)
	}
	return ps, nil
}

// --- Primitive Loading from Keyset Files ---

// LoadSigner loads the Signer primitive from a keyset file.
// It expects the primary key in the keyset to be a signing key.
func LoadSigner(path string) (tink.Signer, error) {
	ps, err := getPrimitivesFromKeysetFile(path)
	if err != nil {
		return nil, err // Error already contains context
	}
	signer, ok := ps.Primary.Primitive.(tink.Signer)
	if !ok {
		return nil, fmt.Errorf("primary primitive in keyset %q is not a tink.Signer", path)
	}
	return signer, nil
}

// LoadSignerFromValue loads the Signer primitive from a keyset JSON string.
func LoadSignerFromValue(jsonKeyset string) (tink.Signer, error) {
	ps, err := getPrimitivesFromKeysetValue(jsonKeyset)
	if err != nil {
		return nil, err
	}
	signer, ok := ps.Primary.Primitive.(tink.Signer)
	if !ok {
		return nil, errors.New("primary primitive in keyset value is not a tink.Signer")
	}
	return signer, nil
}

// LoadDecrypter loads the HybridDecrypt primitive from a keyset file.
// It searches for the first available hybrid decryption key in the keyset.
func LoadDecrypter(path string) (tink.HybridDecrypt, error) {
	ps, err := getPrimitivesFromKeysetFile(path)
	if err != nil {
		return nil, err // Error already contains context
	}
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
	ps, err := getPrimitivesFromKeysetFile(path)
	if err != nil {
		return nil, err // Error already contains context
	}
	verifier, ok := ps.Primary.Primitive.(tink.Verifier)
	if !ok {
		return nil, fmt.Errorf("primary primitive in keyset %q is not a tink.Verifier", path)
	}
	return verifier, nil
}

// LoadEncrypter loads the HybridEncrypt primitive from a keyset file.
// It searches for the first available hybrid encryption key in the keyset.
func LoadEncrypter(path string) (tink.HybridEncrypt, error) {
	ps, err := getPrimitivesFromKeysetFile(path)
	if err != nil {
		return nil, err // Error already contains context
	}
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
