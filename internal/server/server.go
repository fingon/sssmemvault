package server

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"

	"github.com/fingon/sssmemvault/internal/auth"
	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/crypto"
	"github.com/fingon/sssmemvault/internal/store"
	pb "github.com/fingon/sssmemvault/proto"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// SssMemVaultServer implements the proto.SssMemVaultServer interface.
type SssMemVaultServer struct {
	pb.UnimplementedSssMemVaultServer // Embed for forward compatibility
	store                             *store.InMemoryStore
	cfg                               *config.Config
	nodeName                          string // The name of the node running this server instance.
}

// NewSssMemVaultServer creates a new server instance.
func NewSssMemVaultServer(s *store.InMemoryStore, cfg *config.Config, myName string) (*SssMemVaultServer, error) {
	if s == nil {
		return nil, errors.New("store cannot be nil")
	}
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	// Daemon needs both signer (for sync calls) and decrypter (for GetDecoded)
	if cfg.PrivKeySigner == nil {
		return nil, errors.New("config is missing private key signer")
	}
	if cfg.PrivKeyDecrypter == nil {
		return nil, errors.New("config is missing private key decrypter")
	}
	if myName == "" {
		return nil, errors.New("myName cannot be empty")
	}
	return &SssMemVaultServer{
		store:    s,
		cfg:      cfg,
		nodeName: myName,
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

		// --- Proceed with standard node name authentication for other methods ---
		slog.Debug("AuthInterceptor: performing node name authentication", "method", info.FullMethod)

		// 1. Extract Metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			slog.Warn("AuthInterceptor: missing metadata from context", "method", info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, "Missing authentication metadata")
		}

		// 2. Extract Node Name, Timestamp, and Signature
		nodeNames := md.Get(auth.GRPCMetadataNodeNameKey)
		timestamps := md.Get(auth.GRPCMetadataTimestampKey)
		signatures := md.Get(auth.GRPCMetadataSignatureKey)

		if len(nodeNames) == 0 || len(timestamps) == 0 || len(signatures) == 0 {
			slog.Warn("AuthInterceptor: missing required headers", "method", info.FullMethod,
				"name_hdr", auth.GRPCMetadataNodeNameKey, "name_count", len(nodeNames),
				"ts_hdr", auth.GRPCMetadataTimestampKey, "ts_count", len(timestamps),
				"sig_hdr", auth.GRPCMetadataSignatureKey, "sig_count", len(signatures))
			return nil, status.Errorf(codes.Unauthenticated, "Missing %s, %s, or %s header",
				auth.GRPCMetadataNodeNameKey, auth.GRPCMetadataTimestampKey, auth.GRPCMetadataSignatureKey)
		}
		// Use only the first value if multiple are sent
		requestingNodeName := nodeNames[0]
		timestampStr := timestamps[0]
		signatureB64 := signatures[0]

		// 3. Verify Request using Node Name
		err := auth.VerifyRequest(requestingNodeName, timestampStr, signatureB64, cfg)
		if err != nil {
			slog.Warn("AuthInterceptor: request verification failed", "node_name", requestingNodeName, "method", info.FullMethod, "err", err)
			// Return Unauthenticated for security reasons, even if the underlying issue was different (e.g., unknown peer)
			return nil, status.Errorf(codes.Unauthenticated, "Request authentication failed: %v", err)
		}

		slog.Debug("AuthInterceptor: authentication successful", "node_name", requestingNodeName, "method", info.FullMethod)

		// Add authenticated node name to context for handlers
		ctx = context.WithValue(ctx, auth.GRPCMetadataNodeNameKey, requestingNodeName)

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

// --- GetDecoded Helpers ---

// getRequestingNodeName extracts the authenticated node name from the context.
func getRequestingNodeName(ctx context.Context) (string, error) {
	requestingNodeNameVal := ctx.Value(auth.GRPCMetadataNodeNameKey)
	requestingNodeName, ok := requestingNodeNameVal.(string)
	if !ok || requestingNodeName == "" {
		// This should not happen if the interceptor ran correctly
		slog.Error("GetDecoded: failed to get authenticated node name from context")
		return "", status.Error(codes.Internal, "Failed to identify requesting node")
	}
	slog.Debug("GetDecoded: requesting node", "name", requestingNodeName)
	return requestingNodeName, nil
}

// authorizeReader checks if the requesting node is authorized to read the entry.
func authorizeReader(entry *pb.Entry, requestingNodeName string) error {
	// Requires Go 1.21+ for slices.Contains
	if !slices.Contains(entry.Readers, requestingNodeName) {
		slog.Warn("GetDecoded permission denied: requesting node not in readers list",
			"key", entry.Key,
			"requesting_node_name", requestingNodeName,
			"readers", entry.Readers)
		return status.Errorf(codes.PermissionDenied, "Node %q is not authorized to read key %q", requestingNodeName, entry.Key)
	}
	slog.Debug("GetDecoded: reader authorized", "key", entry.Key, "reader_name", requestingNodeName)
	return nil
}

// findAndDecryptOwnFragments finds the fragments owned by the current node and decrypts them.
func (self *SssMemVaultServer) findAndDecryptOwnFragments(entry *pb.Entry) ([][]byte, error) {
	fragmentList, ok := entry.OwnerFragments[self.nodeName]
	if !ok || fragmentList == nil || len(fragmentList.Fragments) == 0 {
		slog.Error("GetDecoded failed: this node does not own a fragment list for the requested entry",
			"key", entry.Key,
			"timestamp", entry.Timestamp.AsTime(),
			"node_name", self.nodeName,
			"owner_names", maps.Keys(entry.OwnerFragments)) // Requires Go 1.21+ for maps.Keys
		return nil, status.Errorf(codes.NotFound, "This node (%s) does not hold a fragment list for key %q", self.nodeName, entry.Key)
	}
	slog.Debug("GetDecoded: found encrypted fragment list for this node", "key", entry.Key, "node_name", self.nodeName, "fragment_count", len(fragmentList.Fragments))

	decryptedFragments := make([][]byte, 0, len(fragmentList.Fragments))
	for i, encFrag := range fragmentList.Fragments {
		decFrag, err := crypto.DecryptFragment(self.cfg.PrivKeyDecrypter, encFrag)
		if err != nil {
			slog.Error("GetDecoded failed: could not decrypt one of the owned fragments",
				"key", entry.Key,
				"timestamp", entry.Timestamp.AsTime(),
				"node_name", self.nodeName,
				"fragment_index", i,
				"err", err)
			return nil, status.Errorf(codes.Internal, "Failed to decrypt owned fragment %d for key %q: %v", i, entry.Key, err)
		}
		decryptedFragments = append(decryptedFragments, decFrag)
		slog.Debug("GetDecoded: successfully decrypted owned fragment", "key", entry.Key, "node_name", self.nodeName, "fragment_index", i)
	}
	return decryptedFragments, nil
}

// findRequestorEncrypter finds the public key encrypter for the requesting node from the loaded config.
func (self *SssMemVaultServer) findRequestorEncrypter(requestingNodeName string) (tink.HybridEncrypt, error) {
	requestorPeerCfg, ok := self.cfg.LoadedPeers[requestingNodeName]
	if !ok {
		slog.Error("GetDecoded failed: could not find config entry for requesting node", "requesting_node_name", requestingNodeName)
		return nil, status.Errorf(codes.Internal, "Configuration error: missing config for peer %s", requestingNodeName)
	}
	if requestorPeerCfg.PubKeyEncrypter == nil {
		// This should not happen if config loading succeeded for this peer
		slog.Error("GetDecoded failed: could not find loaded public key encrypter for requesting node",
			"requesting_node_name", requestingNodeName, "public_key_path", requestorPeerCfg.PublicKeyPath)
		return nil, status.Errorf(codes.Internal, "Configuration error: missing public key encrypter for peer %s (path: %s)", requestingNodeName, requestorPeerCfg.PublicKeyPath)
	}
	slog.Debug("GetDecoded: found public key encrypter for requestor", "requesting_node_name", requestingNodeName)
	return requestorPeerCfg.PubKeyEncrypter, nil
}

// reEncryptFragmentsForRequestor re-encrypts the decrypted fragments using the requestor's public key.
func reEncryptFragmentsForRequestor(decryptedFragments [][]byte, requestorEncrypter tink.HybridEncrypt, key, requestingNodeName string) ([][]byte, error) {
	fragmentsForRequestor := make([][]byte, 0, len(decryptedFragments))
	for i, decFrag := range decryptedFragments {
		encFrag, err := crypto.EncryptFragment(requestorEncrypter, decFrag)
		if err != nil {
			slog.Error("GetDecoded failed: could not re-encrypt fragment for requestor",
				"key", key,
				"requesting_node_name", requestingNodeName,
				"fragment_index", i,
				"err", err)
			return nil, status.Errorf(codes.Internal, "Failed to re-encrypt fragment %d for requestor %s: %v", i, requestingNodeName, err)
		}
		fragmentsForRequestor = append(fragmentsForRequestor, encFrag)
		slog.Debug("GetDecoded: successfully re-encrypted fragment for requestor", "key", key, "requesting_node_name", requestingNodeName, "fragment_index", i)
	}
	return fragmentsForRequestor, nil
}

// GetDecoded returns the decrypted SSS fragment for the calling node,
// provided the node is listed in the entry's readers list.
func (self *SssMemVaultServer) GetDecoded(ctx context.Context, req *pb.GetDecodedRequest) (*pb.GetDecodedResponse, error) {
	slog.Debug("Handling GetDecoded request", "key", req.Key, "timestamp", req.Timestamp.AsTime())
	if req.Key == "" || req.Timestamp == nil {
		return nil, status.Error(codes.InvalidArgument, "Key and timestamp are required")
	}

	// 1. Get Requesting Node Name
	requestingNodeName, err := getRequestingNodeName(ctx)
	if err != nil {
		return nil, err // Error already logged and formatted
	}

	// 2. Get the requested entry from the store
	entry, err := self.store.GetEntry(req.Key, req.Timestamp)
	if err != nil {
		slog.Warn("GetDecoded request failed: entry not found or timestamp mismatch", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "err", err)
		return nil, status.Errorf(codes.NotFound, "Entry not found or timestamp mismatch for key %q: %v", req.Key, err)
	}

	// 3. Authorize Reader
	if err := authorizeReader(entry, requestingNodeName); err != nil {
		return nil, err // Error already logged and formatted
	}

	// 4. Find and Decrypt Fragments Owned by This Node
	decryptedFragments, err := self.findAndDecryptOwnFragments(entry)
	if err != nil {
		return nil, err // Error already logged and formatted
	}

	// 5. Find Requestor's Public Key Encrypter
	requestorEncrypter, err := self.findRequestorEncrypter(requestingNodeName)
	if err != nil {
		return nil, err // Error already logged and formatted
	}

	// 6. Re-encrypt Fragments for Requestor
	fragmentsForRequestor, err := reEncryptFragmentsForRequestor(decryptedFragments, requestorEncrypter, req.Key, requestingNodeName)
	if err != nil {
		return nil, err // Error already logged and formatted
	}

	// 7. Return the list of re-encrypted fragments
	resp := &pb.GetDecodedResponse{
		EncryptedFragments: fragmentsForRequestor, // Use the correct field name
	}
	slog.Info("GetDecoded request successful", "key", req.Key, "timestamp", req.Timestamp.AsTime(), "requesting_node_name", requestingNodeName, "fragment_count", len(fragmentsForRequestor))
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
