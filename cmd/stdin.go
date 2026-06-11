package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

const setAttrFlag = "set-attr"

func addSetAttrFlag(cmd *cobra.Command) {
	cmd.Flags().StringArray(setAttrFlag, nil, "set source attribute for stdin content as key=value (repeatable)")
}

func mustGetSetAttrs(cmd *cobra.Command) map[string]string {
	values, err := cmd.Flags().GetStringArray(setAttrFlag)
	if err != nil {
		loggingFatalFlag(setAttrFlag, err)
	}
	attrs, err := parseSetAttrValues(values)
	if err != nil {
		loggingFatalFlag(setAttrFlag, err)
	}
	return attrs
}

func parseSetAttrValues(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	attrs := make(map[string]string, len(values))
	for _, value := range values {
		key, attrValue, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("must be key=value")
		}
		if key == "" {
			return nil, fmt.Errorf("key cannot be empty")
		}
		attrs[key] = attrValue
	}
	return attrs, nil
}

func loggingFatalFlag(name string, err error) {
	logging.Fatal().Err(err).Msgf("invalid --%s value", name)
}

func init() {
	rootCmd.AddCommand(stdInCmd)
	addSetAttrFlag(stdInCmd)
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
	attrs := mustGetSetAttrs(cmd)
	path := attrs[sources.AttrPath]

	findings, err := detector.DetectSource(
		cmd.Context(),
		&sources.File{
			Content:         os.Stdin,
			Path:            path,
			Attributes:      attrs,
			ShouldSkip:      detector.SkipFunc(),
			MaxArchiveDepth: detector.MaxArchiveDepth,
		},
	)

	if err != nil {
		// log fatal to exit, no need to continue since a report will not be
		// generated when scanning from a pipe...for now
		logging.Fatal().Err(err).Msg("failed scan input from stdin")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
