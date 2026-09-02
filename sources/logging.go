package sources

import (
	"context"
	"log/slog"

	"github.com/betterleaks/betterleaks/logging"
)

var discardLogger = slog.New(slog.DiscardHandler)

// loggerOrDiscard keeps source logging opt-in without requiring nil checks at
// individual log sites. Sources are often initialized with struct literals, so
// nil is the natural zero value for an unattached logger.
func loggerOrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return discardLogger
	}
	return logger
}

func logTrace(ctx context.Context, logger *slog.Logger, msg string, args ...any) {
	if ctx == nil {
		ctx = context.Background()
	}
	loggerOrDiscard(logger).Log(ctx, logging.LevelTrace, msg, args...)
}
