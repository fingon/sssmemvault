package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	"github.com/fingon/sssmemvault/internal/server"
	"github.com/fingon/sssmemvault/internal/store"
	"github.com/fingon/sssmemvault/internal/synchronizer"
	pb "github.com/fingon/sssmemvault/proto"
	"google.golang.org/grpc"
)

const (
	DefaultConfigCheckInterval = 1 * time.Minute
	DefaultPidFile             = "/var/run/sssmemvaultd.pid" // Default PID file path
	DefaultLogFile             = "/var/log/sssmemvaultd.log" // Default log file path
)

// Config holds the specific configuration needed for the daemon subcommand.
type Config struct {
	ConfigPath          string        `kong:"name='config',short='c',default='config.yaml',help='Path to the configuration file.'"`
	MyName              string        `kong:"name='my-name',required,help='This node\\'s unique name (must match a key in config peers).'"`
	Detach              bool          `kong:"name='detach',short='d',help='Run the daemon in the background.'"`
	PidFile             string        `kong:"name='pidfile',default='${pid_file_default}',help='Path to the PID file when detaching.',env='SSSMEMVAULT_PIDFILE'"`
	LogFile             string        `kong:"name='logfile',default='${log_file_default}',help='Path to the log file when detaching.',env='SSSMEMVAULT_LOGFILE'"`
	ConfigCheckInterval time.Duration `kong:"name='config-check-interval',default='${config_check_interval_default}',help='How often to check the config file for changes (e.g., 60s, 5m). 0 disables reloading.'"`
	// LogLevel is handled globally (but needs consideration for detached logging)

	// Internal fields for default value injection by Kong
	PidFileDefault             string `kong:"-"`
	LogFileDefault             string `kong:"-"`
	ConfigCheckIntervalDefault string `kong:"-"`
}

// --- Global State for Reloading ---

// reloadSignal is used to trigger a configuration reload internally (e.g., by file watcher).
var reloadSignal = make(chan struct{}, 1)

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
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP) // Add SIGHUP for reload trigger
	return signalChan
}

// startServices starts the gRPC server and synchronizer in background goroutines.
// It returns channels to monitor their completion/errors.
func startServices(ctx context.Context, grpcServer *grpc.Server, lis net.Listener, syncr *synchronizer.Synchronizer) (grpcErrChan chan error, syncDoneChan chan struct{}) {
	grpcErrChan = make(chan error, 1)
	syncDoneChan = make(chan struct{})

	// Start synchronizer
	go func() {
		defer close(syncDoneChan) // Ensure channel is closed when goroutine exits
		syncr.Start(ctx)          // Start blocks until context is cancelled
		syncr.Stop()              // Wait for poll loops to finish after context cancellation
		slog.Debug("Synchronizer goroutine finished")
	}()

	// Start GRPC server
	go func() {
		slog.Info("Starting GRPC server...")
		grpcErrChan <- grpcServer.Serve(lis)
	}()

	return grpcErrChan, syncDoneChan
}

// stopServices gracefully stops the gRPC server and signals the synchronizer to stop.
// It waits for the synchronizer to finish.
func stopServices(grpcServer *grpc.Server, cancel context.CancelFunc, syncDoneChan chan struct{}) {
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
		grpcServer.Stop() // Force stop if graceful fails
	}

	// 2. Signal the synchronizer to stop via context cancellation
	slog.Info("Signaling synchronizer to stop via context cancellation...")
	cancel()

	// 3. Wait for the synchronizer goroutine to finish
	slog.Debug("Waiting for synchronizer to finish...")
	<-syncDoneChan // Wait until the sync goroutine's defer close(syncDoneChan) runs
	slog.Info("Synchronizer stopped.")
}

// watchConfigFile monitors the configuration file for changes and signals a reload.
func watchConfigFile(ctx context.Context, configPath string, checkInterval time.Duration) {
	if checkInterval <= 0 {
		slog.Info("Config file change monitoring disabled.")
		return
	}
	slog.Info("Starting config file watcher", "path", configPath, "interval", checkInterval)

	var lastModTime time.Time
	var lastHash string

	// Get initial state
	info, err := os.Stat(configPath)
	if err == nil {
		lastModTime = info.ModTime()
		hash, hashErr := calculateFileHash(configPath)
		if hashErr != nil {
			slog.Warn("Could not calculate initial config file hash", "path", configPath, "err", hashErr)
			// Proceed without hash check initially, rely on mod time only for first change
		} else {
			lastHash = hash
		}
		slog.Debug("Initial config state recorded", "mod_time", lastModTime, "hash", lastHash)
	} else {
		slog.Warn("Could not get initial config file info, will retry", "path", configPath, "err", err)
		// lastModTime remains zero, will trigger check on first successful stat
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			info, err := os.Stat(configPath)
			if err != nil {
				// Log warning but continue, maybe file is temporarily unavailable
				slog.Warn("Error stating config file during check", "path", configPath, "err", err)
				continue
			}

			currentModTime := info.ModTime()
			// Check if mod time is newer OR if we haven't successfully recorded a mod time yet
			if currentModTime.After(lastModTime) || lastModTime.IsZero() {
				// Mod time changed (or first successful check), now check hash
				currentHash, hashErr := calculateFileHash(configPath)
				if hashErr != nil {
					slog.Warn("Error calculating config file hash during check", "path", configPath, "err", hashErr)
					// Don't reload if we can't verify the content hash
					continue
				}

				// Reload if hash is different OR if we couldn't get an initial hash
				if currentHash != lastHash || lastHash == "" {
					slog.Info("Config file change detected, signaling reload", "path", configPath, "old_mod_time", lastModTime, "new_mod_time", currentModTime, "old_hash", lastHash, "new_hash", currentHash)
					lastModTime = currentModTime
					lastHash = currentHash
					// Non-blocking send to reloadSignal
					select {
					case reloadSignal <- struct{}{}:
						slog.Debug("Reload signal sent")
					default:
						slog.Warn("Reload signal channel full, reload already pending?")
					}
				} else {
					// Mod time changed, but hash is identical. Update mod time but don't reload.
					slog.Debug("Config file mod time changed, but hash is identical. Ignoring.", "path", configPath)
					lastModTime = currentModTime
				}
			}
		case <-ctx.Done():
			slog.Info("Stopping config file watcher due to context cancellation.")
			return
		}
	}
}

// calculateFileHash calculates the SHA256 hash of a file's content.
func calculateFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %q for hashing: %w", filePath, err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// runCoreDaemonLogic sets up and runs the main daemon services within a loop for reloading.
func runCoreDaemonLogic(daemonCfg *Config) int {
	var appCfg *config.Config
	var localStore *store.InMemoryStore
	var syncr *synchronizer.Synchronizer
	var grpcServer *grpc.Server
	var lis net.Listener
	var err error

	// Main loop for handling reloads
	for {
		slog.Info("Loading configuration and initializing services...")
		appCfg, err = loadDaemonConfig(daemonCfg.ConfigPath)
		if err != nil {
			slog.Error("Initialization failed", "step", "load config", "err", err)
			// If config fails to load on startup or reload, it's likely fatal.
			return 1
		}

		// Validate keys required for daemon operation
		if appCfg.PrivKeySigner == nil || appCfg.PrivKeyDecrypter == nil {
			slog.Error("Initialization failed: Daemon requires both signing and decryption keys loaded from private_key_path", "path", appCfg.PrivateKeyPath)
			return 1
		}

		// Initialize store (re-initialize if reloading, using potentially new master key)
		localStore, err = initializeStore(appCfg)
		if err != nil {
			slog.Error("Initialization failed", "step", "initialize store", "err", err)
			return 1
		}

		// Create a context for this run cycle (cancelled on shutdown or reload)
		runCtx, runCancel := context.WithCancel(context.Background())

		// Initialize synchronizer (re-initialize if reloading)
		syncr, err = synchronizer.NewSynchronizer(appCfg, localStore, daemonCfg.MyName)
		if err != nil {
			slog.Error("Initialization failed", "step", "initialize synchronizer", "err", err)
			runCancel() // Clean up context
			return 1
		}

		// Setup gRPC server (re-initialize if reloading)
		grpcServer, lis, err = setupGRPCServer(appCfg, localStore, daemonCfg.MyName)
		if err != nil {
			slog.Error("Initialization failed", "step", "setup gRPC server", "err", err)
			runCancel() // Clean up context
			// Attempt to close listener if it was created
			if lis != nil {
				_ = lis.Close()
			}
			return 1
		}

		// Start services for this cycle
		grpcErrChan, syncDoneChan := startServices(runCtx, grpcServer, lis, syncr)

		// Start config watcher for this cycle
		// Use a separate context for the watcher that's also cancelled by runCancel
		watcherCtx, watcherCancel := context.WithCancel(runCtx)
		var watcherWg sync.WaitGroup
		watcherWg.Add(1)
		go func() {
			defer watcherWg.Done()
			watchConfigFile(watcherCtx, daemonCfg.ConfigPath, daemonCfg.ConfigCheckInterval)
		}()

		slog.Info("Daemon services started successfully. Waiting for signals...")

		// Wait for shutdown signal, reload signal, or gRPC server error
		signalChan := setupSignalHandling()
		exitCode := 0
		keepRunning := true

		select {
		case err := <-grpcErrChan:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				slog.Error("GRPC server failed", "err", err)
				exitCode = 1 // Indicate error on exit
			} else {
				slog.Info("GRPC server stopped cleanly")
			}
			keepRunning = false // Exit loop on gRPC error or clean stop
		case sig := <-signalChan:
			slog.Info("Received OS signal", "signal", sig)
			if sig == syscall.SIGHUP {
				slog.Info("SIGHUP received, initiating configuration reload...")
				// Signal reload by breaking inner select; loop will continue
			} else {
				// SIGINT or SIGTERM
				slog.Info("Shutdown signal received, initiating graceful shutdown...")
				keepRunning = false // Exit loop
			}
		case <-reloadSignal:
			slog.Info("Internal reload signal received, initiating configuration reload...")
			// Break inner select; loop will continue
		case <-runCtx.Done():
			// Should not happen unless explicitly cancelled elsewhere, but handle defensively
			slog.Warn("Daemon run context cancelled unexpectedly")
			keepRunning = false
		}

		// --- Cleanup for this cycle ---
		slog.Info("Stopping services for current cycle...")
		watcherCancel()                                   // Stop config watcher first
		watcherWg.Wait()                                  // Wait for watcher goroutine to finish
		stopServices(grpcServer, runCancel, syncDoneChan) // Stops gRPC, cancels context, waits for sync

		if !keepRunning {
			slog.Info("Exiting daemon loop.")
			return exitCode // Exit the main function and return
		}

		// If we are here, it means a reload was triggered (SIGHUP or internal signal)
		slog.Info("Reloading configuration and restarting services...")
		// Loop continues to reload config and restart services
	}
}

// Run starts the sssmemvault daemon, handling the main lifecycle including reloads.
func Run(daemonCfg *Config) int {
	slog.Info("Starting sssmemvaultd daemon process...")
	// The core logic is now in a loop within runCoreDaemonLogic
	exitCode := runCoreDaemonLogic(daemonCfg)
	slog.Info("sssmemvaultd daemon process finished.", "exit_code", exitCode)
	return exitCode
}
