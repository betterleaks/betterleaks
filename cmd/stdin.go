package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

type StdinCmd struct {
	ScanFlags `embed:""`
	SetAttr   []string `name:"set-attr" sep:"none" help:"Set a source attribute as key=value (repeatable)."`
}

func (cmd *StdinCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runStdIn(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runStdIn(runtime *commandRuntime, globals *GlobalFlags, options *StdinCmd) {
	// start timer
	start := time.Now()

	// setup config (aka, the thing that defines rules)
	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config()

	// create detector
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, "", detect.WithJobs(resolveJobPlan(options.Jobs, streamJobProfile).Detector))

	// parse flag(s)
	attrs, err := parseSetAttrValues(options.SetAttr)
	if err != nil {
		logging.Fatal().Err(err).Msg("invalid --set-attr value")
	}

	findings := mustNewFindingCollector(&options.ScanFlags, globals.NoColor, runtime.stdout)
	source := newStdinSource(runtime.stdin, attrs, detector.SkipFunc(), options.MaxArchiveDepth)
	summary, scanErr := detector.Scan(runtime.Context, source, findings.Add)
	if scanErr != nil {
		logging.Fatal().Err(scanErr).Msg("failed scan input from stdin")
	}

	findingSummaryAndExit(runtime, summary, detector.ValidationEnabled(), findings, options.ExitCode, start, nil)
}

func newStdinSource(content io.Reader, attrs map[string]string, shouldSkip sources.SkipFunc, maxArchiveDepth int) sources.Source {
	return &sources.Stdin{
		Content:         content,
		Attributes:      attrs,
		ShouldSkip:      shouldSkip,
		MaxArchiveDepth: maxArchiveDepth,
	}
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
