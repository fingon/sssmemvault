package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/node"
	"github.com/fingon/sssmemvault/internal/server"
	"github.com/fingon/sssmemvault/internal/store"
	"github.com/fingon/sssmemvault/internal/synchronizer"
	pb "github.com/fingon/sssmemvault/proto"
	_ "github.com/google/tink/go/keyset" // Import for keyset Handle creation/loading
	"google.golang.org/grpc"
)

// CLI holds the command-line arguments and flags.
type CLI struct {
	ConfigPath string `kong:"name='config',short='c',default='config.yaml',help='Path to the configuration file.'"`
	LogLevel   string `kong:"name='loglevel',enum='debug,info,warn,error',default='info',help='Log level (debug, info, warn, error).'"`
}

func main() {
	var cli CLI
	kctx := kong.Parse(&cli)
	exitCode := runApp(&cli)
	kctx.Exit(exitCode) // Use Kong's exit handler
}

// runApp contains the core application logic and returns an exit code.
func runApp(cli *CLI) int {
	// --- Setup Logging ---
	var level slog.Level
	switch cli.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		// Should be caught by Kong's enum validation, but handle defensively.
		fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", cli.LogLevel)
		return 1
	}
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(logHandler))

	slog.Info("Starting sssmemvaultd...")
	slog.Info("Using configuration file", "path", cli.ConfigPath)

	// --- Initialize Tink ---
	// Register primitives - do this before loading any keys.
	// Note: Tink registration (like signature.Register(), etc.) is often done
	// via side-effect imports (e.g., `_ "github.com/google/tink/go/signature/subtle"`).
	// Ensure necessary Tink modules are imported for side effects if not already.
	// Error handling omitted for brevity, but should be checked in production
	// aead.Register()
	// signature.Register()
	// hybrid.Register()
	slog.Debug("Tink primitives should be registered via imports") // Adjusted log message

	// --- Load Configuration ---
	cfg, err := config.LoadConfig(cli.ConfigPath)
	if err != nil {
		slog.Error("Failed to load configuration", "path", cli.ConfigPath, "err", err)
		return 1
	}

	// --- Initialize Store ---
	localStore, err := store.NewInMemoryStore(cfg.MasterPubKey)
	if err != nil {
		slog.Error("Failed to initialize in-memory store", "err", err)
		return 1
	}
	slog.Info("In-memory store initialized")

	// --- Connect to Peers ---
	peerNodes := make(map[string]*node.PeerNode)
	for ip, peerCfg := range cfg.Peers {
		localIP := ip
		localPeerCfg := peerCfg

		// Connect synchronously for simplicity, could be done concurrently
		peerNode, err := node.ConnectToPeer(localIP, &localPeerCfg)
		if err != nil {
			// Log error but continue, maybe the peer will come online later
			slog.Error("Failed to connect to peer", "peer_ip", localIP, "endpoint", localPeerCfg.Endpoint, "err", err)
			// Optionally: Implement retry logic here or in the synchronizer
		} else {
			peerNodes[localIP] = peerNode
			// Defer closing connections on shutdown
			defer func(pn *node.PeerNode) {
				if pn != nil {
					err := pn.Close()
					if err != nil {
						slog.Warn("Error closing connection to peer", "peer_ip", pn.IP, "err", err)
					}
				}
			}(peerNode)
		}
	}
	slog.Info("Attempted connections to all configured peers", "connected_count", len(peerNodes), "config_count", len(cfg.Peers))

	// --- Initialize Synchronizer ---
	syncr, err := synchronizer.NewSynchronizer(cfg, localStore, peerNodes)
	if err != nil {
		slog.Error("Failed to initialize synchronizer", "err", err)
		return 1 // Synchronizer is critical
	}

	// --- Setup GRPC Server ---
	lis, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		slog.Error("Failed to listen on address", "address", cfg.ListenAddress, "err", err)
		return 1
	}
	slog.Info("Listening for GRPC requests", "address", cfg.ListenAddress)

	// Create GRPC server with interceptor
	authInterceptor := server.AuthInterceptor(cfg)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor),
		// TODO: Add TLS credentials grpc.Creds(...)
	)

	// Create and register the service implementation
	sssServer, err := server.NewSssMemVaultServer(localStore, cfg)
	if err != nil {
		slog.Error("Failed to create SSS MemVault server implementation", "err", err)
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
		if err != nil {
			slog.Error("GRPC server failed", "err", err)
			exitCode = 1 // Indicate failure
		} else {
			slog.Info("GRPC server stopped unexpectedly (but gracefully reported)")
			// Might still be considered an error depending on expectations
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
			grpcServer.Stop()
		}

		// 2. Stop the synchronizer
		slog.Info("Stopping synchronizer...")
		syncr.Stop() // This waits for poll loops to finish

		// 3. Context cancellation (already deferred) will signal any other background tasks

		slog.Info("Shutdown complete.")
		// Exit code remains 0 for graceful shutdown via signal
	}

	return exitCode
}
