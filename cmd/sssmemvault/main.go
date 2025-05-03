package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/fingon/sssmemvault/internal/daemon"
	"github.com/fingon/sssmemvault/internal/genkeys"
	"github.com/fingon/sssmemvault/internal/get"
	"github.com/fingon/sssmemvault/internal/push"
	godaemon "github.com/sevlyar/go-daemon" // Aliased to avoid conflict with internal daemon pkg
	// --- Register Tink Primitives ---
	// Import Tink primitives for side effects (registration)
	// Ensure all necessary primitives used by any command are registered here.
	_ "github.com/tink-crypto/tink-go/v2/aead"             // Register standard AEAD key types
	_ "github.com/tink-crypto/tink-go/v2/aead/subtle"      // Needed for some hybrid encryption key types if used indirectly
	_ "github.com/tink-crypto/tink-go/v2/hybrid"           // Register standard Hybrid key types
	_ "github.com/tink-crypto/tink-go/v2/hybrid/subtle"    // For DHKEM_X25519 etc. used in hybrid encryption/decryption
	_ "github.com/tink-crypto/tink-go/v2/keyset"           // For keyset Handle creation/loading
	_ "github.com/tink-crypto/tink-go/v2/signature"        // Register standard Signature key types
	_ "github.com/tink-crypto/tink-go/v2/signature/subtle" // For ED25519, ECDSA used in signing/verification
	_ "github.com/tink-crypto/tink-go/v2/tink"             // Core Tink library
)

// Global CLI flags
var cli struct {
	LogLevel string `kong:"name='loglevel',enum='debug,info,warn,error',default='info',help='Log level (debug, info, warn, error).',env='SSSMEMVAULT_LOGLEVEL'"`

	Daemon  daemon.Config  `kong:"cmd,help='Run the sssmemvault daemon node.'"`
	Push    push.Config    `kong:"cmd,help='Push a new secret entry to target nodes.'"`
	Get     get.Config     `kong:"cmd,help='Retrieve and reconstruct a secret from owner nodes.'"`
	GenKeys genkeys.Config `kong:"cmd,help='Generate combined private and public keyset files.'"`
}

// setupLogging configures the global slog logger based on the provided level string.
// It returns the configured level.
func setupLogging(logLevel string) (slog.Level, error) {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		// This should ideally be caught by CLI validation (e.g., kong enum)
		return level, fmt.Errorf("invalid log level: %s", logLevel) // Corrected return
	}
	// Log to stderr by default. Will be overridden if detached.
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(logHandler))
	slog.Debug("Default logging setup complete", "level", logLevel)
	return level, nil // Corrected return
}

// setupDetachedLogging redirects logging to a file when running detached.
func setupDetachedLogging(logFile string, level slog.Level) error {
	// Open the log file
	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", logFile, err)
	}
	// Note: We don't close the file here, as the detached process needs it.
	// The OS will close it on process exit.

	// Create a new handler writing to the file
	logHandler := slog.NewTextHandler(file, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(logHandler))
	slog.Info("Logging redirected to file for detached mode", "file", logFile, "level", level)
	return nil
}

func main() {
	kctx := kong.Parse(&cli,
		kong.Name("sssmemvault"),
		kong.Description("A Shamir Secret Sharing based in-memory vault client and daemon."),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		// Inject default values for daemon flags
		kong.Vars{
			"pid_file_default":              daemon.DefaultPidFile,
			"log_file_default":              daemon.DefaultLogFile,
			"config_check_interval_default": daemon.DefaultConfigCheckInterval.String(),
		},
	)

	// --- Setup Logging ---
	// Do this *after* parsing flags so LogLevel is available.
	logLevel, err := setupLogging(cli.LogLevel) // Capture logLevel
	if err != nil {
		// Use fmt directly as logging might not be set up
		_, _ = os.Stderr.WriteString("Error setting up logging: " + err.Error() + "\n") // Best effort write
		os.Exit(1)
	}

	// --- Execute Command ---
	var exitCode int
	switch kctx.Command() {
	case "daemon":
		// --- Handle Detach ---
		if cli.Daemon.Detach {
			cntxt := &godaemon.Context{ // Use alias godaemon
				PidFileName: cli.Daemon.PidFile,
				PidFilePerm: 0o644,
				LogFileName: cli.Daemon.LogFile, // Redirect stdout/stderr to log file
				LogFilePerm: 0o644,
				WorkDir:     "/",   // Or keep current? Consider making configurable if needed.
				Umask:       0o027, // Restrict file permissions created by daemon
				// Args are passed automatically if needed, but Run uses the struct
			}

			d, err := cntxt.Reborn()
			if err != nil {
				slog.Error("Failed to detach daemon process", "err", err)
				kctx.Exit(1) // Use Kong's exit
			}
			if d != nil {
				// Parent process: successfully detached, exit gracefully.
				fmt.Printf("Daemon detached with PID %d, logging to %s\n", d.Pid, cli.Daemon.LogFile)
				kctx.Exit(0)
			}
			// Child process (daemon): execution continues below.
			// Need to release the context resources in the child.
			defer func() {
				if err := cntxt.Release(); err != nil {
					// Log error, but don't exit, daemon should continue
					slog.Error("Failed to release daemon context", "err", err)
				}
			}()

			// Reconfigure logging to use the specified log file in the detached process
			if err := setupDetachedLogging(cli.Daemon.LogFile, logLevel); err != nil { // Pass logLevel
				slog.Error("Failed to set up detached logging", "err", err)
				// Continue execution, but logging might still go to original stderr (now redirected)
			}
			slog.Info("Daemon process started successfully in background", "pid", os.Getpid())
		}
		// Run the actual daemon logic (either in foreground or detached child)
		exitCode = daemon.Run(&cli.Daemon)
	case "push":
		exitCode = push.Run(&cli.Push)
	case "get":
		exitCode = get.Run(&cli.Get)
	case "gen-keys", "genkeys": // Allow alias
		exitCode = genkeys.Run(&cli.GenKeys)
	default:
		// Should be caught by Kong, but handle defensively.
		slog.Error("Unknown command", "command", kctx.Command())
		exitCode = 1
	}

	kctx.Exit(exitCode) // Use Kong's exit handler
}
