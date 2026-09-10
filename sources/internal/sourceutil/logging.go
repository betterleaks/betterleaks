package sourceutil

import (
	"context"
	"log/slog"

	"github.com/betterleaks/betterleaks/v2/logging"
)

var discardLogger = slog.New(slog.DiscardHandler)

// LoggerOrDiscard keeps source logging opt-in without requiring nil checks at
// individual log sites. Sources are often initialized with struct literals, so
// nil is the natural zero value for an unattached logger.
func LoggerOrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return discardLogger
	}
	return logger
}

func LogTrace(ctx context.Context, logger *slog.Logger, msg string, args ...any) {
	if ctx == nil {
		ctx = context.Background()
	}
	LoggerOrDiscard(logger).Log(ctx, logging.LevelTrace, msg, args...)
}
