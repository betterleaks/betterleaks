package cmd

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

type StdinCmd struct {
	ScanFlags `embed:""`
	SetAttr   []string `group:"source" name:"set-attr" sep:"none" help:"Set a source attribute as key=value (repeatable)."`
}

func (cmd *StdinCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runStdIn(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runStdIn(runtime *commandRuntime, globals *GlobalFlags, options *StdinCmd) {
	// start timer
	start := time.Now()

	// setup config (aka, the thing that defines rules)
	cfg := initConfig(runtime, globals, &options.ScanFlags)
	initDiagnostics(runtime, &options.ScanFlags)

	// create runner
	filters, err := loadScanFilters(runtime, cfg, options.IgnoreFile, "")
	if err != nil {
		runtime.fatal("unable to prepare scan", "error", err)
		return
	}
	runner, err := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))
	if err != nil {
		runtime.fatal("unable to prepare scan", "error", err)
		return
	}

	// parse flag(s)
	attrs, err := parseSetAttrValues(options.SetAttr)
	if err != nil {
		runtime.fatal("invalid --set-attr value", "error", err)
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "stdin")
	source := newStdinSource(runtime.stdin, attrs, filters.shouldSkip)
	findings.startScan(runtime)
	summary, scanErr := runner.Scan(runtime.Context, source, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("failed scan input from stdin", "error", scanErr)
	}

	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}

func newStdinSource(content io.Reader, attrs map[string]string, shouldSkip sources.SkipFunc) sources.Source {
	return &sources.Reader{
		Content:    content,
		Attributes: attrs,
		ShouldSkip: shouldSkip,
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
