package node

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/fingon/sssmemvault/internal/auth"
	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure" // Use insecure for now, consider TLS later
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// PeerNode represents a connection and client interface to a peer sssmemvault node.
type PeerNode struct {
	IP     string
	Config *config.PeerConfig
	Conn   *grpc.ClientConn
	Client pb.SssMemVaultClient
}

// ConnectToPeer establishes a GRPC connection to a peer node.
func ConnectToPeer(ip string, peerCfg *config.PeerConfig) (*PeerNode, error) {
	if peerCfg == nil || peerCfg.Endpoint == "" {
		return nil, fmt.Errorf("invalid peer config for IP %s", ip)
	}

	slog.Info("Connecting to peer", "ip", ip, "endpoint", peerCfg.Endpoint)
	// For now, using insecure connections as per README.
	// TODO: Add support for mTLS or other secure transport credentials.
	conn, err := grpc.NewClient(peerCfg.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer %s at %s: %w", ip, peerCfg.Endpoint, err)
	}

	client := pb.NewSssMemVaultClient(conn)

	node := &PeerNode{
		IP:     ip,
		Config: peerCfg,
		Conn:   conn,
		Client: client,
	}
	slog.Info("Successfully connected to peer", "ip", ip, "endpoint", peerCfg.Endpoint)
	return node, nil
}

// Close closes the GRPC connection to the peer.
func (self *PeerNode) Close() error {
	if self.Conn != nil {
		slog.Info("Closing connection to peer", "ip", self.IP, "endpoint", self.Config.Endpoint)
		return self.Conn.Close()
	}
	return nil
}

// --- Client Call Wrappers ---

// createAuthenticatedContext creates a new context with authentication headers.
func createAuthenticatedContext(ctx context.Context, selfPrivKey tink.Signer) (context.Context, error) {
	now := time.Now().UTC()
	// Use RFC3339Nano for precision, compatible with Go's default time.Time marshalling
	// and parsable by time.Parse(time.RFC3339Nano, ...) and time.Parse(time.RFC3339, ...)
	timestampStr := now.Format(time.RFC3339Nano)

	sigBytes, err := crypto.SignData(selfPrivKey, []byte(timestampStr))
	if err != nil {
		return nil, fmt.Errorf("failed to sign timestamp: %w", err)
	}
	signatureB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Create metadata and add to context
	md := metadata.New(map[string]string{
		auth.GRPCMetadataTimestampKey: timestampStr,
		auth.GRPCMetadataSignatureKey: signatureB64,
	})
	authedCtx := metadata.NewOutgoingContext(ctx, md)
	return authedCtx, nil
}

// CallList performs the List RPC call to the peer node.
func (self *PeerNode) CallList(ctx context.Context, selfPrivKey tink.Signer) (*pb.ListResponse, error) {
	authedCtx, err := createAuthenticatedContext(ctx, selfPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated context for List call to %s: %w", self.IP, err)
	}

	slog.Debug("Calling List on peer", "peer_ip", self.IP)
	resp, err := self.Client.List(authedCtx, &pb.ListRequest{})
	if err != nil {
		// Log GRPC status code if available
		st, _ := status.FromError(err)
		slog.Warn("List call to peer failed", "peer_ip", self.IP, "err", err, "grpc_code", st.Code())
		return nil, fmt.Errorf("List call to peer %s failed: %w", self.IP, err)
	}
	slog.Debug("List call to peer successful", "peer_ip", self.IP, "entry_count", len(resp.Entries))
	return resp, nil
}

// CallGet performs the Get RPC call to the peer node.
func (self *PeerNode) CallGet(ctx context.Context, selfPrivKey tink.Signer, req *pb.GetRequest) (*pb.GetResponse, error) {
	authedCtx, err := createAuthenticatedContext(ctx, selfPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated context for Get call to %s: %w", self.IP, err)
	}

	slog.Debug("Calling Get on peer", "peer_ip", self.IP, "key", req.Key, "timestamp", req.Timestamp.AsTime())
	resp, err := self.Client.Get(authedCtx, req)
	if err != nil {
		st, _ := status.FromError(err)
		slog.Warn("Get call to peer failed", "peer_ip", self.IP, "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err, "grpc_code", st.Code())
		return nil, fmt.Errorf("Get call to peer %s failed for key %s: %w", self.IP, req.Key, err)
	}
	slog.Debug("Get call to peer successful", "peer_ip", self.IP, "key", req.Key)
	return resp, nil
}

// CallGetDecoded performs the GetDecoded RPC call to the peer node.
// Note: This is less common for the synchronizer but might be used by other clients.
func (self *PeerNode) CallGetDecoded(ctx context.Context, selfPrivKey tink.Signer, req *pb.GetDecodedRequest) (*pb.GetDecodedResponse, error) {
	authedCtx, err := createAuthenticatedContext(ctx, selfPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated context for GetDecoded call to %s: %w", self.IP, err)
	}

	slog.Debug("Calling GetDecoded on peer", "peer_ip", self.IP, "key", req.Key, "timestamp", req.Timestamp.AsTime())
	resp, err := self.Client.GetDecoded(authedCtx, req)
	if err != nil {
		st, _ := status.FromError(err)
		slog.Warn("GetDecoded call to peer failed", "peer_ip", self.IP, "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err, "grpc_code", st.Code())
		return nil, fmt.Errorf("GetDecoded call to peer %s failed for key %s: %w", self.IP, req.Key, err)
	}
	slog.Debug("GetDecoded call to peer successful", "peer_ip", self.IP, "key", req.Key)
	return resp, nil
}
