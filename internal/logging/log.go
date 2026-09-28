package logging

import (
	"context"
	"log/slog"
	"os"
)

const (
	// LevelTrace is lower than slog.LevelDebug so verbose tracing remains
	// separately selectable.
	LevelTrace = slog.LevelDebug - 4
	// LevelFatal is higher than slog.LevelError so --log-level=fatal continues
	// to suppress non-fatal errors.
	LevelFatal = slog.LevelError + 4
)

var discardLogger = slog.New(slog.DiscardHandler)

// OrDiscard returns logger, or a shared logger that discards output when logger is nil.
// It does not change the process-wide default logger.
func OrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return discardLogger
	}
	return logger
}

// Fatal logs an error and terminates the process. It is intended for command
// entry points; reusable packages should return errors instead.
func Fatal(msg string, args ...any) {
	slog.Default().Log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}
