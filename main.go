package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/betterleaks/betterleaks/v2/cmd"
)

// defaultGCPercent trades heap headroom for fewer collections. A scan keeps a
// small live heap but allocates a fresh chunk per fragment, so at the Go
// default the collector ran every few milliseconds and its pauses, assists,
// and pool flushes dominated wall time on many-core hosts. GOGC in the
// environment still wins.
const defaultGCPercent = 400

func main() {
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(defaultGCPercent)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd.ExecuteContext(ctx)
}
