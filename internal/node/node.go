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
	if name == "" {
		return nil, errors.New("peer name cannot be empty")
	}
	if peerCfg == nil {
		return nil, fmt.Errorf("missing peer config for name %s", name)
	}
	// Endpoint is required for connection, but public key path is needed for operations
	if peerCfg.Endpoint == "" {
		return nil, fmt.Errorf("peer config for %s is missing endpoint", name)
	}
	if peerCfg.PublicKeyPath == "" {
		// This should be caught by config loading, but check defensively
		return nil, fmt.Errorf("peer config for %s is missing public_key_path", name)
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
		Config: peerCfg, // Store the pointer to the config containing loaded keys
		Conn:   conn,
		Client: client,
	}
	slog.Info("Successfully connected to peer", "name", name, "endpoint", peerCfg.Endpoint)
	return node, nil
}

// Close closes the GRPC connection to the peer.
func (self *PeerNode) Close() error {
	if self.Conn != nil {
		slog.Info("Closing connection to peer", "name", self.Name, "endpoint", self.Config.Endpoint) // Use endpoint from config
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
	if selfPrivKey == nil {
		return nil, errors.New("private key signer cannot be nil for authenticated context")
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

// makeAuthenticatedClientCall is a generic helper to make authenticated gRPC calls.
// It handles context creation, logging, and error wrapping.
func makeAuthenticatedClientCall[ReqT, RespT any](
	ctx context.Context,
	slog *slog.Logger,
	grpcClient pb.SssMemVaultClient,
	clientName string,
	clientPrivKey tink.Signer,
	req ReqT,
	callFunc func(ctx context.Context, c pb.SssMemVaultClient, in ReqT, opts ...grpc.CallOption) (RespT, error),
	methodNameForLog string, // e.g., "List", "Get"
) (RespT, error) {
	var zero RespT // Zero value for the response type

	authedCtx, err := createAuthenticatedContext(ctx, clientName, clientPrivKey)
	if err != nil {
		return zero, fmt.Errorf("failed to create authenticated context for %s call: %w", methodNameForLog, err)
	}

	slog = slog.With("client_name", clientName)
	slog.Debug("Calling remote node", "method", methodNameForLog)

	resp, err := callFunc(authedCtx, grpcClient, req)
	if err != nil {
		st, _ := status.FromError(err)
		slog.Warn(methodNameForLog+" call failed", "err", err, "grpc_code", st.Code())
		return zero, fmt.Errorf("%s call failed: %w", methodNameForLog, err)
	}

	slog.Debug(methodNameForLog+" call successful", "response_type", fmt.Sprintf("%T", resp))
	return resp, nil
}

// CallListFromClient performs the List RPC call using a provided client interface.
func CallListFromClient(ctx context.Context, client pb.SssMemVaultClient, clientName string, clientPrivKey tink.Signer, req *pb.ListRequest) (*pb.ListResponse, error) {
	slog := slog.Default()
	return makeAuthenticatedClientCall(ctx, slog, client, clientName, clientPrivKey, req,
		func(cCtx context.Context, c pb.SssMemVaultClient, in *pb.ListRequest, opts ...grpc.CallOption) (*pb.ListResponse, error) {
			return c.List(cCtx, in, opts...)
		},
		"List",
	)
}

// CallGetFromClient performs the Get RPC call using a provided client interface.
func CallGetFromClient(ctx context.Context, client pb.SssMemVaultClient, clientName string, clientPrivKey tink.Signer, req *pb.GetRequest) (*pb.GetResponse, error) {
	slog := slog.With("key", req.Key, "timestamp", req.Timestamp.AsTime())
	return makeAuthenticatedClientCall(ctx, slog, client, clientName, clientPrivKey, req,
		func(cCtx context.Context, c pb.SssMemVaultClient, in *pb.GetRequest, opts ...grpc.CallOption) (*pb.GetResponse, error) {
			return c.Get(cCtx, in, opts...)
		},
		"Get",
	)
}

// CallGetDecodedFromClient performs the GetDecoded RPC call using a provided client interface.
func CallGetDecodedFromClient(ctx context.Context, client pb.SssMemVaultClient, clientName string, clientPrivKey tink.Signer, req *pb.GetDecodedRequest) (*pb.GetDecodedResponse, error) {
	slog := slog.With("key", req.Key, "timestamp", req.Timestamp.AsTime())

	return makeAuthenticatedClientCall(ctx, slog, client, clientName, clientPrivKey, req,
		func(cCtx context.Context, c pb.SssMemVaultClient, in *pb.GetDecodedRequest, opts ...grpc.CallOption) (*pb.GetDecodedResponse, error) {
			return c.GetDecoded(cCtx, in, opts...)
		},
		"GetDecoded",
	)
}
