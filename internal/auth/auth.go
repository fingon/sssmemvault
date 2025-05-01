package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
)

const (
	// GRPCMetadataTimestampKey is the key for the timestamp in GRPC metadata.
	GRPCMetadataTimestampKey = "x-request-timestamp"
	// GRPCMetadataSignatureKey is the key for the signature in GRPC metadata.
	GRPCMetadataSignatureKey = "x-request-signature"
	// GRPCMetadataNodeNameKey is the key for the requesting node's name in GRPC metadata.
	GRPCMetadataNodeNameKey = "x-request-node-name"
)

// VerifyRequest extracts authentication details (node name, timestamp, signature)
// and verifies them against the node's configuration.
func VerifyRequest(requestingNodeName, requestTimestampStr, signatureB64 string, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("configuration is nil")
	}
	if cfg.LoadedPeers == nil {
		return errors.New("peer configuration not loaded")
	}
	if requestingNodeName == "" {
		return errors.New("requesting node name cannot be empty")
	}

	// 1. Find Peer Config and Public Key using the Node Name
	peerCfg, ok := cfg.LoadedPeers[requestingNodeName]
	if !ok {
		slog.Warn("Authentication failed: requesting node name not found in peer configuration", "requesting_node_name", requestingNodeName)
		return fmt.Errorf("authentication failed: requesting node %q not configured as a peer", requestingNodeName)
	}

	// 2. Check Public Key Verifier (essential for signature check)
	if peerCfg.PubKeyVerifier == nil {
		// This should not happen if config loading succeeded for this peer
		slog.Error("Internal error: peer config found but public key verifier is nil", "configured_peer_name", requestingNodeName, "public_key_path", peerCfg.PublicKeyPath)
		return fmt.Errorf("internal error: missing public key verifier for peer %s (path: %s)", requestingNodeName, peerCfg.PublicKeyPath)
	}

	// 3. Parse Timestamp
	requestTime, err := time.Parse(time.RFC3339Nano, requestTimestampStr)
	if err != nil {
		// Try parsing without nanos for compatibility
		requestTime, err = time.Parse(time.RFC3339, requestTimestampStr)
		if err != nil {
			slog.Warn("Authentication failed: invalid timestamp format", "node_name", requestingNodeName, "timestamp", requestTimestampStr, "err", err)
			return fmt.Errorf("authentication failed: invalid timestamp format: %w", err)
		}
	}

	// 4. Check Timestamp Skew
	now := time.Now().UTC()
	skew := now.Sub(requestTime)
	if skew < 0 {
		skew = -skew // Absolute difference
	}

	if skew > cfg.MaxTimestampSkew {
		slog.Warn("Authentication failed: timestamp skew too large",
			"node_name", requestingNodeName,
			"request_time", requestTime,
			"server_time", now,
			"skew", skew,
			"max_skew", cfg.MaxTimestampSkew)
		return fmt.Errorf("authentication failed: timestamp skew too large (skew: %s, max: %s)", skew, cfg.MaxTimestampSkew)
	}

	// 5. Decode Signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		slog.Warn("Authentication failed: invalid base64 signature", "node_name", requestingNodeName, "err", err)
		return fmt.Errorf("authentication failed: invalid base64 signature: %w", err)
	}

	// 6. Verify Signature using the configured peer's public key
	// The signature must be over the exact timestamp string that was sent.
	dataToVerify := []byte(requestTimestampStr)
	err = crypto.VerifySignature(peerCfg.PubKeyVerifier, dataToVerify, signatureBytes)
	if err != nil {
		// Don't wrap the crypto error directly, just indicate signature failure.
		slog.Warn("Authentication failed: invalid signature", "requesting_node_name", requestingNodeName, "configured_peer_name", requestingNodeName, "err", err) // Log underlying error
		return errors.New("authentication failed: invalid signature")
	}

	slog.Debug("Authentication successful", "requesting_node_name", requestingNodeName)
	return nil
}
