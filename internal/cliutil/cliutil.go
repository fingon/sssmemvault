package cliutil

import (
	"fmt"
	"log/slog"
	"os"
)

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

// EnsureTinkPrimitivesRegistered logs a debug message reminding that Tink primitives
// should be registered via side-effect imports in the main package.
func EnsureTinkPrimitivesRegistered() {
	// Ensure necessary Tink primitives are registered via side-effect imports
	// in the main package(s) that use them.
	slog.Debug("Tink primitives should be registered via imports in the main package")
}
