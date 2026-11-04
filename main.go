package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/betterleaks/betterleaks/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// A second signal uses the default handler if graceful shutdown stalls.
		stop()
	}()
	cmd.ExecuteContext(ctx)
}
