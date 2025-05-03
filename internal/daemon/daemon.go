package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
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

// --- Helper Functions ---

// loadDaemonConfig loads the application configuration.
func loadDaemonConfig(configPath string) (*config.Config, error) {
	slog.Info("Loading configuration file", "path", configPath)
	appCfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	return appCfg, nil
}

// initializeStore creates the in-memory store.
func initializeStore(appCfg *config.Config) (*store.InMemoryStore, error) {
	localStore, err := store.NewInMemoryStore(appCfg.MasterPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize in-memory store: %w", err)
	}
	slog.Info("In-memory store initialized")
	return localStore, nil
}

// setupGRPCServer configures and creates the gRPC server instance and listener.
func setupGRPCServer(appCfg *config.Config, localStore *store.InMemoryStore, myName string) (*grpc.Server, net.Listener, error) {
	lis, err := net.Listen("tcp", appCfg.ListenAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on address %s: %w", appCfg.ListenAddress, err)
	}
	slog.Info("Listening for GRPC requests", "address", appCfg.ListenAddress)

	authInterceptor := server.AuthInterceptor(appCfg)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor),
		// TODO: Add TLS credentials grpc.Creds(...)
	)

	sssServer, err := server.NewSssMemVaultServer(localStore, appCfg, myName)
	if err != nil {
		_ = lis.Close() // Clean up listener
		return nil, nil, fmt.Errorf("failed to create SSS MemVault server implementation: %w", err)
	}
	pb.RegisterSssMemVaultServer(grpcServer, sssServer)
	slog.Info("GRPC server configured and service registered")
	return grpcServer, lis, nil
}

// setupSignalHandling sets up handling for SIGINT and SIGTERM.
func setupSignalHandling() chan os.Signal {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	return signalChan
}

// startServices starts the gRPC server and synchronizer in background goroutines.
func startServices(ctx context.Context, grpcServer *grpc.Server, lis net.Listener, syncr *synchronizer.Synchronizer) chan error {
	grpcErrChan := make(chan error, 1)

	// Start synchronizer
	syncr.Start(ctx)

	// Start GRPC server
	go func() {
		slog.Info("Starting GRPC server...")
		grpcErrChan <- grpcServer.Serve(lis)
	}()

	return grpcErrChan
}

// handleShutdown orchestrates the graceful shutdown of services.
func handleShutdown(sig os.Signal, grpcServer *grpc.Server, syncr *synchronizer.Synchronizer, cancel context.CancelFunc) {
	slog.Info("Received signal, initiating shutdown...", "signal", sig)

	// 1. Stop GRPC server gracefully
	slog.Info("Attempting graceful GRPC server shutdown...")
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()
	stopTimeout := 15 * time.Second
	select {
	case <-stopped:
		slog.Info("GRPC server shut down gracefully")
	case <-time.After(stopTimeout):
		slog.Warn("GRPC server graceful shutdown timed out, forcing stop")
		grpcServer.Stop()
	}

	// 2. Stop the synchronizer (signal via context cancellation)
	slog.Info("Stopping synchronizer via context cancellation...")
	cancel() // Signal synchronizer and other potential background tasks

	// 3. Wait for synchronizer to finish
	syncr.Stop() // This waits for poll loops to finish

	slog.Info("Shutdown complete.")
}

// Run starts the sssmemvault daemon.
func Run(daemonCfg *Config) int {
	slog.Info("Starting sssmemvaultd daemon...")

	appCfg, err := loadDaemonConfig(daemonCfg.ConfigPath)
	if err != nil {
		slog.Error("Initialization failed", "step", "load config", "err", err)
		return 1
	}

	// Validate that the required keys were loaded for the daemon
	if appCfg.PrivKeySigner == nil || appCfg.PrivKeyDecrypter == nil {
		slog.Error("Initialization failed: Daemon requires both signing and decryption keys loaded from private_key_path", "path", appCfg.PrivateKeyPath)
		return 1
	}

	localStore, err := initializeStore(appCfg)
	if err != nil {
		slog.Error("Initialization failed", "step", "initialize store", "err", err)
		return 1
	}

	// Use background context for peer connections and services
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure context is cancelled on exit

	syncr, err := synchronizer.NewSynchronizer(appCfg, localStore, daemonCfg.MyName)
	if err != nil {
		slog.Error("Initialization failed", "step", "initialize synchronizer", "err", err)
		return 1
	}

	grpcServer, lis, err := setupGRPCServer(appCfg, localStore, daemonCfg.MyName)
	if err != nil {
		slog.Error("Initialization failed", "step", "setup gRPC server", "err", err)
		return 1
	}

	grpcErrChan := startServices(ctx, grpcServer, lis, syncr)
	signalChan := setupSignalHandling()

	exitCode := 0 // Default to success

	// Wait for shutdown signal or gRPC server error
	select {
	case err := <-grpcErrChan:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			slog.Error("GRPC server failed", "err", err)
			exitCode = 1
		} else {
			slog.Info("GRPC server stopped")
		}
		// If gRPC stops unexpectedly, cancel context to stop synchronizer
		cancel()
		syncr.Stop() // Wait for synchronizer after cancellation
	case sig := <-signalChan:
		handleShutdown(sig, grpcServer, syncr, cancel)
		// Exit code remains 0 for graceful shutdown via signal
	}

	// Final context cancellation if not already done
	cancel()

	return exitCode
}
