package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	"google.golang.org/grpc/peer"
)

const (
	// GRPCMetadataTimestampKey is the key for the timestamp in GRPC metadata.
	GRPCMetadataTimestampKey = "x-request-timestamp"
	// GRPCMetadataSignatureKey is the key for the signature in GRPC metadata.
	GRPCMetadataSignatureKey = "x-request-signature"
)

// VerifyRequest extracts authentication details (peer IP, timestamp, signature)
// and verifies them against the node's configuration.
func VerifyRequest(peerIP, requestTimestampStr, signatureB64 string, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("configuration is nil")
	}
	if cfg.LoadedPeers == nil {
		return errors.New("peer configuration not loaded")
	}

	// 1. Find Peer Config and Public Key
	peerCfg, ok := cfg.LoadedPeers[peerIP]
	if !ok {
		slog.Warn("Authentication failed: unknown peer IP", "peer_ip", peerIP)
		return fmt.Errorf("authentication failed: unknown peer IP %s", peerIP)
	}
	if peerCfg.PubKeyVerifier == nil {
		// This should not happen if config loading is correct
		slog.Error("Internal error: peer config found but public key verifier is nil", "peer_ip", peerIP)
		return fmt.Errorf("internal error: missing public key for peer %s", peerIP)
	}

	// 2. Parse Timestamp
	requestTime, err := time.Parse(time.RFC3339Nano, requestTimestampStr)
	if err != nil {
		// Try parsing without nanos for compatibility
		requestTime, err = time.Parse(time.RFC3339, requestTimestampStr)
		if err != nil {
			slog.Warn("Authentication failed: invalid timestamp format", "peer_ip", peerIP, "timestamp", requestTimestampStr, "err", err)
			return fmt.Errorf("authentication failed: invalid timestamp format: %w", err)
		}
	}

	// 3. Check Timestamp Skew
	now := time.Now().UTC()
	skew := now.Sub(requestTime)
	if skew < 0 {
		skew = -skew // Absolute difference
	}

	if skew > cfg.MaxTimestampSkew {
		slog.Warn("Authentication failed: timestamp skew too large",
			"peer_ip", peerIP,
			"request_time", requestTime,
			"server_time", now,
			"skew", skew,
			"max_skew", cfg.MaxTimestampSkew)
		return fmt.Errorf("authentication failed: timestamp skew too large (skew: %s, max: %s)", skew, cfg.MaxTimestampSkew)
	}

	// 4. Decode Signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		slog.Warn("Authentication failed: invalid base64 signature", "peer_ip", peerIP, "err", err)
		return fmt.Errorf("authentication failed: invalid base64 signature: %w", err)
	}

	// 5. Verify Signature
	// The signature must be over the exact timestamp string that was sent.
	dataToVerify := []byte(requestTimestampStr)
	err = crypto.VerifySignature(peerCfg.PubKeyVerifier, dataToVerify, signatureBytes)
	if err != nil {
		// Don't wrap the crypto error directly, just indicate signature failure.
		slog.Warn("Authentication failed: invalid signature", "peer_ip", peerIP, "err", err) // Log underlying error
		return errors.New("authentication failed: invalid signature")
	}

	slog.Debug("Authentication successful", "peer_ip", peerIP)
	return nil
}

// GetPeerIP extracts the IP address from the GRPC peer information.
func GetPeerIP(p *peer.Peer) (string, error) {
	if p == nil || p.Addr == net.Addr(nil) {
		return "", errors.New("no peer information available")
	}

	switch addr := p.Addr.(type) {
	case *net.TCPAddr:
		return addr.IP.String(), nil
	case *net.UDPAddr:
		return addr.IP.String(), nil
	// Add cases for other address types if necessary (e.g., Unix sockets)
	default:
		// Attempt a generic split if it looks like "ip:port"
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			// Validate if it's actually an IP
			if net.ParseIP(host) != nil {
				return host, nil
			}
		}
		return "", fmt.Errorf("unsupported peer address type: %T", p.Addr)
	}
}
