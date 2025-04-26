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

// checkCIDRAllowed verifies if the requesting IP matches any of the allowed CIDRs for the peer.
// It logs configuration errors for invalid CIDRs but skips them for the check.
func checkCIDRAllowed(requestingIP net.IP, peerIP string, allowedCIDRs []string) bool {
	for _, cidrStr := range allowedCIDRs {
		_, network, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Log config error, but don't fail auth for this specific request based on bad config.
			// A stricter approach could fail here.
			slog.Error("Configuration error: invalid CIDR in allowed_source_cidrs for peer", "peer_ip", peerIP, "cidr", cidrStr, "err", err)
			continue // Skip this invalid CIDR
		}
		if network.Contains(requestingIP) {
			slog.Debug("Source IP check passed", "requesting_ip", requestingIP, "matched_cidr", cidrStr)
			return true // Allowed
		}
	}
	// If loop finishes without finding a match
	slog.Warn("Authentication failed: requesting IP does not match allowed CIDRs for peer", "requesting_ip", requestingIP, "configured_peer_ip", peerIP, "allowed_cidrs", allowedCIDRs)
	return false // Not allowed
}

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
		// If the IP itself isn't in the config, we can't verify anything.
		slog.Warn("Authentication failed: requesting IP not found in peer configuration", "requesting_ip", peerIP)
		return fmt.Errorf("authentication failed: requesting IP %s not configured as a peer", peerIP)
	}

	// 2. Optional: Check Source IP against Allowed CIDRs for the *configured* peer
	if len(peerCfg.AllowedSourceCIDRs) > 0 {
		slog.Debug("Performing source IP CIDR check", "requesting_ip", peerIP, "configured_peer_ip", peerIP, "allowed_cidrs", peerCfg.AllowedSourceCIDRs)
		requestingIP := net.ParseIP(peerIP)
		if requestingIP == nil {
			// This check should ideally happen earlier, but keep it for safety.
			slog.Warn("Authentication failed: could not parse requesting peer IP", "requesting_ip", peerIP)
			return fmt.Errorf("authentication failed: could not parse requesting IP %s", peerIP)
		}

		if !checkCIDRAllowed(requestingIP, peerIP, peerCfg.AllowedSourceCIDRs) {
			// Error details are logged within checkCIDRAllowed
			return fmt.Errorf("authentication failed: requesting IP %s is not allowed by configured CIDRs for peer %s", peerIP, peerIP)
		}
		// If checkCIDRAllowed returns true, proceed.
	} else {
		slog.Debug("Skipping source IP CIDR check (not configured for peer)", "requesting_ip", peerIP, "configured_peer_ip", peerIP)
	}

	// 3. Check Public Key Verifier (essential for signature check)
	if peerCfg.PubKeyVerifier == nil {
		// This should not happen if config loading is correct and peer was found
		slog.Error("Internal error: peer config found but public key verifier is nil", "configured_peer_ip", peerIP)
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

	// 4. Check Timestamp Skew
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

	// 5. Decode Signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		slog.Warn("Authentication failed: invalid base64 signature", "requesting_ip", peerIP, "err", err)
		return fmt.Errorf("authentication failed: invalid base64 signature: %w", err)
	}

	// 6. Verify Signature using the configured peer's public key
	// The signature must be over the exact timestamp string that was sent.
	dataToVerify := []byte(requestTimestampStr)
	err = crypto.VerifySignature(peerCfg.PubKeyVerifier, dataToVerify, signatureBytes)
	if err != nil {
		// Don't wrap the crypto error directly, just indicate signature failure.
		slog.Warn("Authentication failed: invalid signature", "requesting_ip", peerIP, "configured_peer_ip", peerIP, "err", err) // Log underlying error
		return errors.New("authentication failed: invalid signature")
	}

	slog.Debug("Authentication successful", "requesting_ip", peerIP, "configured_peer_ip", peerIP)
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
