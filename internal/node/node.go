package node

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/fingon/sssmemvault/internal/auth"
	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure" // Use insecure for now, consider TLS later
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// PeerNode represents a connection and client interface to a peer sssmemvault node.
// Primarily used by the daemon/synchronizer. Identified by Name.
type PeerNode struct {
	Name   string
	Config *config.PeerConfig // Pointer to the config entry for this peer
	Conn   *grpc.ClientConn
	Client pb.SssMemVaultClient
}

// DialPeer establishes a GRPC connection to a given endpoint.
// Used by client commands (push, get) that might not have full PeerConfig.
// The context parameter is currently unused but kept for consistency with ConnectToPeer.
func DialPeer(_ context.Context, endpoint string) (*grpc.ClientConn, error) {
	slog.Debug("Dialing peer", "endpoint", endpoint)
	// For now, using insecure connections as per README.
	// TODO: Add support for mTLS or other secure transport credentials.
	// Use WithBlock() to make the initial connection synchronous within the context timeout.
	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Block until connected or context expires
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial peer at %s: %w", endpoint, err)
	}
	slog.Debug("Successfully dialed peer", "endpoint", endpoint)
	return conn, nil
}

// ConnectToPeer establishes a GRPC connection to a peer node using its config.
// Used primarily by the daemon/synchronizer. Includes context for timeout.
func ConnectToPeer(ctx context.Context, name string, peerCfg *config.PeerConfig) (*PeerNode, error) {
	if peerCfg == nil || peerCfg.Endpoint == "" {
		return nil, fmt.Errorf("invalid or missing peer config for name %s", name)
	}
	if name == "" {
		return nil, errors.New("peer name cannot be empty")
	}

	slog.Info("Connecting to peer", "name", name, "endpoint", peerCfg.Endpoint)
	conn, err := DialPeer(ctx, peerCfg.Endpoint) // Use DialPeer with context
	if err != nil {
		// DialPeer already wraps the error
		// Log context here as DialPeer doesn't know the name
		slog.Error("Failed to dial peer", "name", name, "endpoint", peerCfg.Endpoint, "err", err)
		return nil, err
	}

	client := pb.NewSssMemVaultClient(conn)

	node := &PeerNode{
		Name:   name,
		Config: peerCfg,
		Conn:   conn,
		Client: client,
	}
	slog.Info("Successfully connected to peer", "name", name, "endpoint", peerCfg.Endpoint)
	return node, nil
}

// Close closes the GRPC connection to the peer.
func (self *PeerNode) Close() error {
	if self.Conn != nil {
		slog.Info("Closing connection to peer", "name", self.Name, "endpoint", self.Config.Endpoint)
		return self.Conn.Close()
	}
	return nil
}

// --- Client Call Wrappers ---

// createAuthenticatedContext creates a new context with authentication headers,
// including the client's node name.
func createAuthenticatedContext(ctx context.Context, clientName string, selfPrivKey tink.Signer) (context.Context, error) {
	if clientName == "" {
		return nil, errors.New("client name cannot be empty for authenticated context")
	}
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
		auth.GRPCMetadataNodeNameKey:  clientName, // Add node name header
	})
	authedCtx := metadata.NewOutgoingContext(ctx, md)
	slog.Debug("Created authenticated context", "client_name", clientName, "timestamp", timestampStr)
	return authedCtx, nil
}

// --- Client Call Wrappers (Used by Daemon/Synchronizer via PeerNode) ---
// These wrappers need the daemon's own name to authenticate requests.

// CallList performs the List RPC call to the peer node associated with PeerNode.
func (self *PeerNode) CallList(ctx context.Context, selfName string, selfPrivKey tink.Signer) (*pb.ListResponse, error) {
	resp, err := CallListFromClient(ctx, self.Client, selfName, selfPrivKey, &pb.ListRequest{})
	if err != nil {
		// Error already logged and wrapped by CallListFromClient
		return nil, fmt.Errorf("List call to peer %s failed: %w", self.Name, err)
	}
	return resp, nil
}

// CallGet performs the Get RPC call to the peer node associated with PeerNode.
func (self *PeerNode) CallGet(ctx context.Context, selfName string, selfPrivKey tink.Signer, req *pb.GetRequest) (*pb.GetResponse, error) {
	resp, err := CallGetFromClient(ctx, self.Client, selfName, selfPrivKey, req)
	if err != nil {
		// Error already logged and wrapped by CallGetFromClient
		return nil, fmt.Errorf("Get call to peer %s failed for key %s: %w", self.Name, req.Key, err)
	}
	return resp, nil
}

// CallGetDecoded performs the GetDecoded RPC call to the peer node associated with PeerNode.
func (self *PeerNode) CallGetDecoded(ctx context.Context, selfName string, selfPrivKey tink.Signer, req *pb.GetDecodedRequest) (*pb.GetDecodedResponse, error) {
	resp, err := CallGetDecodedFromClient(ctx, self.Client, selfName, selfPrivKey, req)
	if err != nil {
		// Error already logged and wrapped by CallGetDecodedFromClient
		return nil, fmt.Errorf("GetDecoded call to peer %s failed for key %s: %w", self.Name, req.Key, err)
	}
	return resp, nil
}

// --- Client Call Helpers (Used directly by client commands like 'get' and by daemon wrappers) ---

// CallListFromClient performs the List RPC call using a provided client interface.
func CallListFromClient(ctx context.Context, client pb.SssMemVaultClient, clientName string, clientPrivKey tink.Signer, req *pb.ListRequest) (*pb.ListResponse, error) {
	authedCtx, err := createAuthenticatedContext(ctx, clientName, clientPrivKey)
	if err != nil {
		// Not including peer name here as it's less relevant for direct client calls
		return nil, fmt.Errorf("failed to create authenticated context for List call: %w", err)
	}

	slog.Debug("Calling List on remote node", "client_name", clientName)
	resp, err := client.List(authedCtx, req)
	if err != nil {
		st, _ := status.FromError(err)
		slog.Warn("List call failed", "err", err, "grpc_code", st.Code())
		return nil, fmt.Errorf("List call failed: %w", err) // Wrap original error
	}
	slog.Debug("List call successful", "entry_count", len(resp.Entries))
	return resp, nil
}

// CallGetFromClient performs the Get RPC call using a provided client interface.
func CallGetFromClient(ctx context.Context, client pb.SssMemVaultClient, clientName string, clientPrivKey tink.Signer, req *pb.GetRequest) (*pb.GetResponse, error) {
	authedCtx, err := createAuthenticatedContext(ctx, clientName, clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated context for Get call: %w", err)
	}

	slog.Debug("Calling Get on remote node", "client_name", clientName, "key", req.Key, "timestamp", req.Timestamp.AsTime())
	resp, err := client.Get(authedCtx, req)
	if err != nil {
		st, _ := status.FromError(err)
		slog.Warn("Get call failed", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err, "grpc_code", st.Code())
		return nil, fmt.Errorf("Get call failed for key %s: %w", req.Key, err)
	}
	slog.Debug("Get call successful", "key", req.Key)
	return resp, nil
}

// CallGetDecodedFromClient performs the GetDecoded RPC call using a provided client interface.
func CallGetDecodedFromClient(ctx context.Context, client pb.SssMemVaultClient, clientName string, clientPrivKey tink.Signer, req *pb.GetDecodedRequest) (*pb.GetDecodedResponse, error) {
	authedCtx, err := createAuthenticatedContext(ctx, clientName, clientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated context for GetDecoded call: %w", err)
	}

	slog.Debug("Calling GetDecoded on remote node", "client_name", clientName, "key", req.Key, "timestamp", req.Timestamp.AsTime())
	resp, err := client.GetDecoded(authedCtx, req)
	if err != nil {
		st, _ := status.FromError(err)
		slog.Warn("GetDecoded call failed", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err, "grpc_code", st.Code())
		return nil, fmt.Errorf("GetDecoded call failed for key %s: %w", req.Key, err)
	}
	slog.Debug("GetDecoded call successful", "key", req.Key)
	return resp, nil
}
