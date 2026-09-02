package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/detect"
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

	cfg := Config(runtime)

	// create detector
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, "", detect.WithJobs(resolveJobPlan(options.Jobs, streamJobProfile).Detector))

	// parse flag(s)
	attrs, err := parseSetAttrValues(options.SetAttr)
	if err != nil {
		runtime.fatal("invalid --set-attr value", "error", err)
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor)
	source := newStdinSource(runtime.stdin, attrs, detector.SkipFunc(), options.MaxArchiveDepth, runtime.Logger())
	summary, scanErr := detector.Scan(runtime.Context, source, findings.Add)
	if scanErr != nil {
		runtime.fatal("failed scan input from stdin", "error", scanErr)
	}

	findingSummaryAndExit(runtime, summary, detector.ValidationEnabled(), findings, options.ExitCode, start, nil)
}

func newStdinSource(content io.Reader, attrs map[string]string, shouldSkip sources.SkipFunc, maxArchiveDepth int, logger *slog.Logger) sources.Source {
	return &sources.Stdin{
		Logger:          logger,
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
