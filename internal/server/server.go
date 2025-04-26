package server

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices" // Requires Go 1.21+

	"github.com/fingon/sssmemvault/internal/auth"
	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/fingon/sssmemvault/internal/store"
	pb "github.com/fingon/sssmemvault/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SssMemVaultServer implements the proto.SssMemVaultServer interface.
type SssMemVaultServer struct {
	pb.UnimplementedSssMemVaultServer // Embed for forward compatibility
	store                             *store.InMemoryStore
	cfg                               *config.Config
	// nodeIP is the IP address of the node running this server instance.
	// Needed for GetDecoded to find the correct encrypted fragment.
	nodeIP string
}

// NewSssMemVaultServer creates a new server instance.
func NewSssMemVaultServer(s *store.InMemoryStore, cfg *config.Config) (*SssMemVaultServer, error) {
	if s == nil {
		return nil, errors.New("store cannot be nil")
	}
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	if cfg.PrivKeyDecrypter == nil {
		return nil, errors.New("config is missing private key decrypter")
	}
	if cfg.MyIP == "" {
		return nil, errors.New("config is missing node IP (my_ip)")
	}
	return &SssMemVaultServer{
		store:  s,
		cfg:    cfg,
		nodeIP: cfg.MyIP,
	}, nil
}

// AuthInterceptor is a unary server interceptor for authenticating requests.
func AuthInterceptor(cfg *config.Config) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		slog.Debug("AuthInterceptor: processing request", "method", info.FullMethod)

		// Skip authentication for the Push method, which relies on master key signature verification
		if info.FullMethod == "/sssmemvault.SssMemVault/Push" {
			slog.Debug("AuthInterceptor: skipping peer auth for Push method")
			return handler(ctx, req)
		}

		// --- Proceed with standard peer authentication for other methods ---
		slog.Debug("AuthInterceptor: performing peer authentication", "method", info.FullMethod)

		// 1. Extract Peer IP
		p, ok := peer.FromContext(ctx)
		if !ok {
			slog.Error("AuthInterceptor: failed to get peer from context", "method", info.FullMethod)
			return nil, status.Error(codes.Internal, "Failed to identify peer")
		}
		peerIP, err := auth.GetPeerIP(p)
		if err != nil {
			slog.Error("AuthInterceptor: failed to extract peer IP", "peer_addr", p.Addr, "err", err)
			return nil, status.Errorf(codes.Internal, "Failed to extract peer IP: %v", err)
		}
		slog.Debug("AuthInterceptor: extracted peer IP", "peer_ip", peerIP)

		// 2. Extract Metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			slog.Warn("AuthInterceptor: missing metadata from context", "peer_ip", peerIP, "method", info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "Missing authentication metadata")
		}

		timestamps := md.Get(auth.GRPCMetadataTimestampKey)
		signatures := md.Get(auth.GRPCMetadataSignatureKey)

		if len(timestamps) == 0 || len(signatures) == 0 {
			slog.Warn("AuthInterceptor: missing timestamp or signature header", "peer_ip", peerIP, "method", info.FullMethod, "timestamps_count", len(timestamps), "signatures_count", len(signatures))
			return nil, status.Errorf(codes.Unauthenticated, "Missing %s or %s header", auth.GRPCMetadataTimestampKey, auth.GRPCMetadataSignatureKey)
		}
		// Use only the first value if multiple are sent
		timestampStr := timestamps[0]
		signatureB64 := signatures[0]

		// 3. Verify Request
		err = auth.VerifyRequest(peerIP, timestampStr, signatureB64, cfg)
		if err != nil {
			slog.Warn("AuthInterceptor: request verification failed", "peer_ip", peerIP, "method", info.FullMethod, "err", err)
			// Return Unauthenticated for security reasons, even if the underlying issue was different (e.g., unknown peer)
			return nil, status.Errorf(codes.Unauthenticated, "Request authentication failed: %v", err)
		}

		slog.Debug("AuthInterceptor: authentication successful", "peer_ip", peerIP, "method", info.FullMethod)

		// Add authenticated peer IP to context for handlers? Maybe not needed if handlers re-extract.
		// ctx = context.WithValue(ctx, "authenticatedPeerIP", peerIP)

		// 4. Proceed to the handler
		return handler(ctx, req)
	}
}

// List returns the metadata of all entries known to this node.
func (self *SssMemVaultServer) List(context.Context, *pb.ListRequest) (*pb.ListResponse, error) {
	slog.Debug("Handling List request")
	metadataList := self.store.ListEntries()
	resp := &pb.ListResponse{
		Entries: metadataList,
	}
	slog.Debug("List request successful", "entry_count", len(metadataList))
	return resp, nil
}

// Get returns the full, signed entry for a specific key and timestamp.
func (self *SssMemVaultServer) Get(_ context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	slog.Debug("Handling Get request", "key", req.Key, "timestamp", req.Timestamp.AsTime())
	if req.Key == "" || req.Timestamp == nil {
		return nil, status.Error(codes.InvalidArgument, "Key and timestamp are required")
	}

	entry, err := self.store.GetEntry(req.Key, req.Timestamp)
	if err != nil {
		slog.Warn("Get request failed: entry not found or timestamp mismatch", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err)
		// Distinguish between not found and other errors if needed
		return nil, status.Errorf(codes.NotFound, "Entry not found or timestamp mismatch for key %q: %v", req.Key, err)
	}

	// The store already verified the signature on add/update, but maybe verify again?
	// err = crypto.VerifyEntrySignature(self.cfg.MasterPubKey, entry)
	// if err != nil {
	//  slog.Error("CRITICAL: Stored entry failed master signature verification!", "key", entry.Key, "err", err)
	// 	return nil, status.Error(codes.Internal, "Stored entry signature invalid")
	// }

	resp := &pb.GetResponse{
		Entry: entry, // Entry is already a clone from the store
	}
	slog.Debug("Get request successful", "key", req.Key, "timestamp", req.Timestamp.AsTime())
	return resp, nil
}

// GetDecoded returns the decrypted SSS fragment for the calling node,
// provided the node is listed in the entry's readers list.
func (self *SssMemVaultServer) GetDecoded(ctx context.Context, req *pb.GetDecodedRequest) (*pb.GetDecodedResponse, error) {
	slog.Debug("Handling GetDecoded request", "key", req.Key, "timestamp", req.Timestamp.AsTime())
	if req.Key == "" || req.Timestamp == nil {
		return nil, status.Error(codes.InvalidArgument, "Key and timestamp are required")
	}

	// 1. Get Peer IP (already authenticated by interceptor, but needed for reader check)
	p, ok := peer.FromContext(ctx)
	if !ok {
		slog.Error("GetDecoded: failed to get peer from context")
		return nil, status.Error(codes.Internal, "Failed to identify peer")
	}
	requestingPeerIP, err := auth.GetPeerIP(p)
	if err != nil {
		slog.Error("GetDecoded: failed to extract peer IP", "peer_addr", p.Addr, "err", err)
		return nil, status.Errorf(codes.Internal, "Failed to extract peer IP: %v", err)
	}
	slog.Debug("GetDecoded: requesting peer", "ip", requestingPeerIP)

	// 2. Get the requested entry from the store
	entry, err := self.store.GetEntry(req.Key, req.Timestamp)
	if err != nil {
		slog.Warn("GetDecoded request failed: entry not found or timestamp mismatch", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err)
		return nil, status.Errorf(codes.NotFound, "Entry not found or timestamp mismatch for key %q: %v", req.Key, err)
	}

	// 3. Check if the requesting peer is in the readers list
	// Requires Go 1.21+ for slices.Contains
	if !slices.Contains(entry.Readers, requestingPeerIP) {
		slog.Warn("GetDecoded permission denied: requesting peer not in readers list",
			"key", req.Key,
			"requesting_peer_ip", requestingPeerIP,
			"readers", entry.Readers)
		return nil, status.Errorf(codes.PermissionDenied, "Peer %s is not authorized to read key %q", requestingPeerIP, req.Key)
	}
	slog.Debug("GetDecoded: reader authorized", "key", req.Key, "reader_ip", requestingPeerIP)

	// 4. Find the encrypted fragment belonging to *this* node (the one handling the request)
	encryptedFragment, ok := entry.OwnerFragments[self.nodeIP]
	if !ok {
		// This means the entry exists, the reader is valid, but this specific node
		// doesn't own a fragment for this entry. This shouldn't typically happen
		// if provisioning is done correctly, but handle it defensively.
		slog.Error("GetDecoded failed: this node does not own a fragment for the requested entry",
			"key", req.Key,
			"timestamp", req.Timestamp.AsTime(),
			"node_ip", self.nodeIP,
			"owner_ips", maps.Keys(entry.OwnerFragments)) // Requires Go 1.21+ for maps.Keys
		return nil, status.Errorf(codes.NotFound, "This node (%s) does not hold a fragment for key %q", self.nodeIP, req.Key)
	}
	slog.Debug("GetDecoded: found encrypted fragment for this node", "key", req.Key, "node_ip", self.nodeIP)

	// 5. Decrypt the fragment using this node's private key
	decryptedFragment, err := crypto.DecryptFragment(self.cfg.PrivKeyDecrypter, encryptedFragment)
	if err != nil {
		// This likely indicates a key mismatch or corrupted data. Critical error.
		slog.Error("GetDecoded failed: could not decrypt fragment",
			"key", req.Key,
			"timestamp", req.Timestamp.AsTime(),
			"node_ip", self.nodeIP,
			"err", err)
		return nil, status.Errorf(codes.Internal, "Failed to decrypt fragment for key %q: %v", req.Key, err)
	}
	slog.Debug("GetDecoded: successfully decrypted fragment", "key", req.Key, "node_ip", self.nodeIP)

	// 6. Return the decrypted fragment
	resp := &pb.GetDecodedResponse{
		DecryptedFragment: decryptedFragment,
	}
	slog.Info("GetDecoded request successful", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "requesting_peer_ip", requestingPeerIP)
	return resp, nil
}

// Push receives a new entry signed by the master key and adds it to the store.
// This method bypasses the standard peer authentication interceptor.
func (self *SssMemVaultServer) Push(_ context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	entry := req.GetEntry()
	if entry == nil || entry.Timestamp == nil || entry.Key == "" {
		slog.Warn("Push request rejected: invalid entry", "entry_nil", entry == nil)
		return nil, status.Error(codes.InvalidArgument, "Invalid entry: cannot be nil, must have timestamp and key")
	}
	slog.Debug("Handling Push request", "key", entry.Key, "timestamp", entry.Timestamp.AsTime())

	// 1. Verify the master signature (this is the primary auth mechanism for Push)
	// Note: The store's AddOrUpdateEntry also verifies, but verifying here first
	// provides a clearer separation of concerns for the Push endpoint's auth.
	err := crypto.VerifyEntrySignature(self.cfg.MasterPubKey, entry)
	if err != nil {
		slog.Warn("Push request rejected: master signature verification failed",
			"key", entry.Key,
			"timestamp", entry.Timestamp.AsTime(),
			"err", err)
		// Return PermissionDenied as the signature is the 'permission' for Push
		return nil, status.Errorf(codes.PermissionDenied, "Master signature verification failed: %v", err)
	}
	slog.Debug("Push request master signature verified successfully", "key", entry.Key)

	// 2. Add the entry to the store
	// AddOrUpdateEntry handles timestamp comparison and potential overwrites,
	// and performs its own signature verification as a safety measure.
	updated, err := self.store.AddOrUpdateEntry(entry)
	if err != nil {
		// This could be a redundant signature failure or another store issue.
		slog.Error("Failed to store entry from Push request",
			"key", entry.Key,
			"timestamp", entry.Timestamp.AsTime(),
			"err", err)
		// Use Internal error code as the signature was already verified once.
		return nil, status.Errorf(codes.Internal, "Failed to store pushed entry: %v", err)
	}

	if updated {
		slog.Info("Successfully processed Push request and updated store", "key", entry.Key, "timestamp", entry.Timestamp.AsTime())
	} else {
		slog.Info("Processed Push request, but store was not updated (entry already exists with same or newer timestamp)", "key", entry.Key, "timestamp", entry.Timestamp.AsTime())
	}

	return &pb.PushResponse{}, nil
}
