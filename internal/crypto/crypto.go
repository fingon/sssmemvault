package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"

	pb "github.com/fingon/sssmemvault/proto"
	"github.com/hashicorp/vault/shamir"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SignData signs the provided data using the Tink Signer primitive.
func SignData(privKey tink.Signer, data []byte) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("private key (signer) is nil")
	}
	sig, err := privKey.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	return sig, nil
}

// VerifySignature verifies the signature of the data using the Tink Verifier primitive.
func VerifySignature(pubKey tink.Verifier, data, signature []byte) error {
	if pubKey == nil {
		return errors.New("public key (verifier) is nil")
	}
	err := pubKey.Verify(signature, data)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// EncryptFragment encrypts a secret fragment using the Tink HybridEncrypt primitive.
// Context info can be added for Associated Data (AD) if needed, nil for now.
func EncryptFragment(pubKey tink.HybridEncrypt, fragment []byte) ([]byte, error) {
	if pubKey == nil {
		return nil, errors.New("public key (encrypter) is nil")
	}
	// contextInfo can be used for additional authenticated data (AAD)
	// For example, could include the entry key or timestamp, but requires careful handling
	// on both encryption and decryption sides. Keeping it nil for simplicity now.
	var contextInfo []byte
	encrypted, err := pubKey.Encrypt(fragment, contextInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt fragment: %w", err)
	}
	return encrypted, nil
}

// DecryptFragment decrypts an encrypted fragment using the Tink HybridDecrypt primitive.
// Context info must match the one used during encryption (nil for now).
func DecryptFragment(privKey tink.HybridDecrypt, encryptedFragment []byte) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("private key (decrypter) is nil")
	}
	// contextInfo must match the one used during encryption.
	var contextInfo []byte
	decrypted, err := privKey.Decrypt(encryptedFragment, contextInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt fragment: %w", err)
	}
	return decrypted, nil
}

// SplitSecret uses Shamir's Secret Sharing to split a secret into parts.
func SplitSecret(secret []byte, parts, threshold int) ([][]byte, error) {
	if threshold > parts || threshold <= 0 || parts <= 0 {
		return nil, fmt.Errorf("invalid split parameters: parts=%d, threshold=%d", parts, threshold)
	}
	if len(secret) == 0 {
		return nil, errors.New("cannot split an empty secret")
	}
	fragments, err := shamir.Split(secret, parts, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret using shamir: %w", err)
	}
	return fragments, nil
}

// CombineFragments uses Shamir's Secret Sharing to reconstruct the secret from fragments.
func CombineFragments(fragments [][]byte) ([]byte, error) {
	if len(fragments) == 0 {
		return nil, errors.New("no fragments provided to combine")
	}
	// Basic validation: check if all fragments have the expected SSS prefix/structure
	for i, f := range fragments {
		if len(f) < 2 { // Minimal check, shamir library does more robust checks
			return nil, fmt.Errorf("fragment %d is too short", i)
		}
	}
	secret, err := shamir.Combine(fragments)
	if err != nil {
		// Error might indicate insufficient *valid* fragments for the threshold
		return nil, fmt.Errorf("failed to combine fragments using shamir: %w", err)
	}
	return secret, nil
}

// --- Entry Signing and Verification ---

// marshalEntryForSigning marshals the Entry fields relevant for signing into a stable byte representation.
// It specifically excludes the signature field itself.
func marshalEntryForSigning(entry *pb.Entry) ([]byte, error) {
	// Create a temporary entry, copying only the fields to be signed.
	// This ensures a consistent structure for signing/verification.
	entryToSign := &pb.Entry{
		Timestamp:      &timestamppb.Timestamp{Seconds: entry.Timestamp.Seconds, Nanos: entry.Timestamp.Nanos}, // Ensure deep copy if mutable
		Key:            entry.Key,
		Readers:        append([]string(nil), entry.Readers...), // Copy slice
		OwnerFragments: maps.Clone(entry.OwnerFragments),
		// Signature field is explicitly omitted
	}

	// Marshal the temporary entry. Use deterministic marshalling if available/needed,
	// but standard proto marshalling is generally stable for the same input struct.
	data, err := proto.Marshal(entryToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entry for signing: %w", err)
	}
	// Return a hash of the marshaled data to sign, reducing signature size
	// and potentially mitigating issues if marshalling isn't perfectly deterministic
	// across all proto library versions (though it usually is). SHA256 is standard.
	hash := sha256.Sum256(data)
	return hash[:], nil // Return the hash slice
}

// SignEntry calculates the data to be signed, signs it with the master private key,
// and updates the entry's signature field.
// NOTE: This function requires the MASTER private key and is typically used
// by a separate provisioning tool, NOT the server nodes themselves.
func SignEntry(masterPrivKey tink.Signer, entry *pb.Entry) error {
	if entry == nil {
		return errors.New("cannot sign a nil entry")
	}
	dataToSign, err := marshalEntryForSigning(entry)
	if err != nil {
		return fmt.Errorf("failed to prepare entry data for signing: %w", err)
	}

	signature, err := SignData(masterPrivKey, dataToSign)
	if err != nil {
		return fmt.Errorf("failed to sign entry data: %w", err)
	}

	entry.Signature = signature
	return nil
}

// VerifyEntrySignature calculates the expected signed data from the entry,
// and verifies the entry's signature field against it using the master public key.
func VerifyEntrySignature(masterPubKey tink.Verifier, entry *pb.Entry) error {
	if entry == nil {
		return errors.New("cannot verify signature of a nil entry")
	}
	if len(entry.Signature) == 0 {
		return errors.New("entry has no signature to verify")
	}

	dataToVerify, err := marshalEntryForSigning(entry)
	if err != nil {
		return fmt.Errorf("failed to prepare entry data for verification: %w", err)
	}

	err = VerifySignature(masterPubKey, dataToVerify, entry.Signature)
	if err != nil {
		// Wrap the error for more context
		return fmt.Errorf("master signature verification failed for key %q timestamp %s: %w", entry.Key, entry.Timestamp.AsTime(), err)
	}

	return nil
}
