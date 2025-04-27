package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/fingon/sssmemvault/internal/cliutil"
	"github.com/fingon/sssmemvault/internal/daemon"
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

	Daemon daemon.Config `kong:"cmd,help='Run the sssmemvault daemon node.'"`
	Push   push.Config   `kong:"cmd,help='Push a new secret entry to target nodes.'"`
	Get    get.Config    `kong:"cmd,help='Retrieve and reconstruct a secret from owner nodes.'"` // get.Config needs HybridPrivateKeyPath
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
	if err := cliutil.SetupLogging(cli.LogLevel); err != nil {
		// Use fmt directly as logging might not be set up
		_, _ = os.Stderr.WriteString("Error setting up logging: " + err.Error() + "\n") // Best effort write
		os.Exit(1)
	}

	// --- Ensure Tink Primitives Registered ---
	// Log a reminder, actual registration happens via imports above.
	cliutil.EnsureTinkPrimitivesRegistered()

	// --- Execute Command ---
	var exitCode int
	switch kctx.Command() {
	case "daemon":
		exitCode = daemon.Run(&cli.Daemon)
	case "push":
		exitCode = push.Run(&cli.Push)
	case "get":
		exitCode = get.Run(&cli.Get)
	default:
		// Should be caught by Kong, but handle defensively.
		slog.Error("Unknown command", "command", kctx.Command())
		exitCode = 1
	}

	kctx.Exit(exitCode) // Use Kong's exit handler
}
