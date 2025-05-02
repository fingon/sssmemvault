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

// SetupLogging configures the global slog logger based on the provided level string.
func SetupLogging(logLevel string) error {
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
		return fmt.Errorf("invalid log level: %s", logLevel)
	}
	// Log to stderr for CLI tools, stdout for daemon potentially
	// For simplicity, using stderr for all now. Can be adjusted.
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(logHandler))
	slog.Debug("Logging setup complete", "level", logLevel)
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
	)

	// --- Setup Logging ---
	// Do this *after* parsing flags so LogLevel is available.
	if err := SetupLogging(cli.LogLevel); err != nil {
		// Use fmt directly as logging might not be set up
		_, _ = os.Stderr.WriteString("Error setting up logging: " + err.Error() + "\n") // Best effort write
		os.Exit(1)
	}

	// --- Execute Command ---
	var exitCode int
	switch kctx.Command() {
	case "daemon":
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
