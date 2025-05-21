package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/fingon/sssmemvault/internal/daemon"
	"github.com/fingon/sssmemvault/internal/genkeys"
	"github.com/fingon/sssmemvault/internal/gensign"
	"github.com/fingon/sssmemvault/internal/get"
	"github.com/fingon/sssmemvault/internal/push"
	// Aliased to avoid conflict with internal daemon pkg
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

type genCLI struct {
	Keys genkeys.Config `cmd:"" help:"Generate combined private and public keyset files."`
	Sign gensign.Config `cmd:"" help:"Generate sign private and public keyset files."`
}

var cli struct {
	LogLevel string `default:"info" enum:"debug,info,warn,error" env:"SSSMEMVAULT_LOGLEVEL" help:"Log level (debug, info, warn, error)."`

	Daemon daemon.Config `cmd:"" help:"Run the sssmemvault daemon node."`
	Gen    genCLI        `cmd:""`
	Get    get.Config    `cmd:"" help:"Retrieve and reconstruct a secret from owner nodes."`
	Push   push.Config   `cmd:"" help:"Push a new secret entry to target nodes."`
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
	_, err := setupLogging(cli.LogLevel) // Capture logLevel
	if err != nil {
		// Use fmt directly as logging might not be set up
		_, _ = os.Stderr.WriteString("Error setting up logging: " + err.Error() + "\n") // Best effort write
		os.Exit(1)
	}

	// --- Execute Command ---
	err = kctx.Run()
	kctx.FatalIfErrorf(err)
}
