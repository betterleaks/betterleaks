package main

import (
	"os"
	"os/signal"

	"github.com/betterleaks/betterleaks/cmd"
	"github.com/betterleaks/betterleaks/logging"
)

func main() {
	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit betterleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	cmd.Execute()
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	logging.Fatal().Msg("Interrupt signal received. Exiting...")
}
