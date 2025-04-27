package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/node"
	"github.com/fingon/sssmemvault/internal/server"
	"github.com/fingon/sssmemvault/internal/store"
	"github.com/fingon/sssmemvault/internal/synchronizer"
	pb "github.com/fingon/sssmemvault/proto"
	"google.golang.org/grpc"
)

// Config holds the specific configuration needed for the daemon subcommand.
type Config struct {
	ConfigPath string `kong:"name='config',short='c',default='config.yaml',help='Path to the configuration file.'"`
	MyName     string `kong:"name='my-name',required,help='This node\\'s unique name (must match a key in config peers).'"`
	// LogLevel is handled globally
}

// Run starts the sssmemvault daemon.
func Run(cfg *Config) int {
	slog.Info("Starting sssmemvaultd daemon...")
	slog.Info("Using configuration file", "path", cfg.ConfigPath)

	// --- Load Configuration ---
	appCfg, err := config.LoadConfig(cfg.ConfigPath)
	if err != nil {
		slog.Error("Failed to load configuration", "path", cfg.ConfigPath, "err", err)
		return 1
	}

	// --- Initialize Store ---
	localStore, err := store.NewInMemoryStore(appCfg.MasterPubKey)
	if err != nil {
		slog.Error("Failed to initialize in-memory store", "err", err)
		return 1
	}
	slog.Info("In-memory store initialized")

	// --- Connect to Peers ---
	peerNodes := make(map[string]*node.PeerNode)
	// Use a separate context for initial peer connections? For now, use background.
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 30*time.Second) // Timeout for initial connections
	defer connectCancel()

	var wgConnect sync.WaitGroup
	var mu sync.Mutex // Protect peerNodes map during concurrent connections

	for name, peerCfgPtr := range appCfg.LoadedPeers { // Iterate over LoadedPeers which has pointers
		// Avoid capturing loop variables directly in goroutine
		localName := name
		localPeerCfgPtr := peerCfgPtr // Capture the pointer for this iteration

		// Skip connecting to self if 'my-name' is in the peers list
		if localName == cfg.MyName {
			slog.Debug("Skipping connection to self", "name", localName)
			continue
		}

		// Skip peers without an endpoint (likely client entries)
		if localPeerCfgPtr.Endpoint == "" {
			slog.Debug("Skipping connection to peer without endpoint", "name", localName)
			continue
		}

		wgConnect.Add(1)
		go func() {
			defer wgConnect.Done()
			peerNode, err := node.ConnectToPeer(connectCtx, localName, localPeerCfgPtr) // Pass connectCtx and pointer
			if err == nil {
				mu.Lock()
				peerNodes[localName] = peerNode
				mu.Unlock()
				// Defer closing connections on shutdown (handled later)
			}
		}()
	}
	wgConnect.Wait() // Wait for all initial connection attempts

	// Defer closing connections
	defer func() {
		slog.Info("Closing peer connections...")
		for name, pn := range peerNodes {
			if pn != nil {
				err := pn.Close()
				if err != nil {
					slog.Warn("Error closing connection to peer", "peer_name", name, "err", err)
				}
			}
		}
	}()

	slog.Info("Attempted connections to all configured peers", "connected_count", len(peerNodes), "config_count", len(appCfg.Peers))

	// --- Initialize Synchronizer ---
	// Pass the map of successfully connected peers and own name
	syncr, err := synchronizer.NewSynchronizer(appCfg, localStore, peerNodes, cfg.MyName)
	if err != nil {
		slog.Error("Failed to initialize synchronizer", "err", err)
		return 1 // Synchronizer is critical
	}

	// --- Setup GRPC Server ---
	lis, err := net.Listen("tcp", appCfg.ListenAddress)
	if err != nil {
		slog.Error("Failed to listen on address", "address", appCfg.ListenAddress, "err", err)
		return 1
	}
	slog.Info("Listening for GRPC requests", "address", appCfg.ListenAddress)

	// Create GRPC server with interceptor
	authInterceptor := server.AuthInterceptor(appCfg)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor),
		// TODO: Add TLS credentials grpc.Creds(...)
	)

	// Create and register the service implementation
	sssServer, err := server.NewSssMemVaultServer(localStore, appCfg, cfg.MyName) // Pass MyName from daemon config
	if err != nil {
		slog.Error("Failed to create SSS MemVault server implementation", "err", err)
		_ = lis.Close() // Clean up listener
		return 1
	}
	pb.RegisterSssMemVaultServer(grpcServer, sssServer)
	slog.Info("GRPC server configured and service registered")

	// --- Start Services ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is cancelled on exit

	// Start synchronizer in background
	syncr.Start(ctx)

	// Start GRPC server in background
	grpcErrChan := make(chan error, 1)
	go func() {
		slog.Info("Starting GRPC server...")
		grpcErrChan <- grpcServer.Serve(lis)
	}()

	// --- Handle Shutdown Gracefully ---
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	exitCode := 0 // Default to success

	select {
	case err := <-grpcErrChan:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) { // Ignore ErrServerStopped from graceful stop
			slog.Error("GRPC server failed", "err", err)
			exitCode = 1 // Indicate failure
		} else {
			slog.Info("GRPC server stopped")
		}
	case sig := <-signalChan:
		slog.Info("Received signal, initiating shutdown...", "signal", sig)

		// 1. Stop GRPC server gracefully
		slog.Info("Attempting graceful GRPC server shutdown...")
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()
		// Wait for graceful stop or timeout
		stopTimeout := 15 * time.Second // Adjust timeout as needed
		select {
		case <-stopped:
			slog.Info("GRPC server shut down gracefully")
		case <-time.After(stopTimeout):
			slog.Warn("GRPC server graceful shutdown timed out, forcing stop")
			grpcServer.Stop() // Force stop
		}

		// 2. Stop the synchronizer (signal via context cancellation)
		slog.Info("Stopping synchronizer via context cancellation...")
		cancel() // Signal synchronizer and other potential background tasks

		// 3. Wait for synchronizer to finish
		syncr.Stop() // This waits for poll loops to finish

		slog.Info("Shutdown complete.")
		// Exit code remains 0 for graceful shutdown via signal
	}

	// Final context cancellation if not already done (e.g., if gRPC server stopped unexpectedly)
	cancel()

	return exitCode
}
