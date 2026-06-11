package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(stdInCmd)
	stdInCmd.Flags().StringArray("set-attr", nil, "set source attribute for stdin content, key=value (repeatable)")
}

var stdInCmd = &cobra.Command{
	Use:   "stdin",
	Short: "detect secrets from stdin",
	Run:   runStdIn,
}

func runStdIn(cmd *cobra.Command, _ []string) {
	// start timer
	start := time.Now()

	// setup config (aka, the thing that defines rules)
	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, "")

	// parse flag(s)
	exitCode := mustGetIntFlag(cmd, "exit-code")
	attrs, err := parseSetAttrFlag(cmd)
	if err != nil {
		logging.Fatal().Err(err).Msg("invalid --set-attr value")
	}

	findings, err := detector.DetectSource(
		cmd.Context(),
		newStdinSource(os.Stdin, attrs, detector.SkipFunc(), detector.MaxArchiveDepth),
	)

	if err != nil {
		// log fatal to exit, no need to continue since a report will not be
		// generated when scanning from a pipe...for now
		logging.Fatal().Err(err).Msg("failed scan input from stdin")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}

func newStdinSource(content io.Reader, attrs map[string]string, shouldSkip sources.SkipFunc, maxArchiveDepth int) sources.Source {
	return &sources.Stdin{
		Content:         content,
		Attributes:      attrs,
		ShouldSkip:      shouldSkip,
		MaxArchiveDepth: maxArchiveDepth,
	}
}

func parseSetAttrFlag(cmd *cobra.Command) (map[string]string, error) {
	values, err := cmd.Flags().GetStringArray("set-attr")
	if err != nil {
		return nil, fmt.Errorf("could not get flag: set-attr: %w", err)
	}
	return parseSetAttrValues(values)
}

func parseSetAttrValues(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	attrs := make(map[string]string, len(values))
	for _, value := range values {
		key, attrValue, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("%q must be in key=value form", value)
		}
		if key == "" {
			return nil, fmt.Errorf("%q has an empty key", value)
		}
		attrs[key] = attrValue
	}

	return attrs, nil
}
