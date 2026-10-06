package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/betterleaks/betterleaks/v2/cmd"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd.ExecuteContext(ctx)
}
