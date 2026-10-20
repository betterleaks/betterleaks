package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"golang.org/x/term"
)

type StdinCmd struct {
	ScanFlags `embed:""`
	GitDiff   bool     `group:"source" name:"git-diff" help:"Parse additions from git log -p or git diff, preserving file paths, commit headers, and line numbers."`
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
	input, closeInput := cancellableStdin(runtime.Context, runtime.stdin)
	defer closeInput()
	source := newStdinSource(input, attrs, filters.shouldSkip)
	if options.GitDiff {
		source = &sources.GitDiff{Content: input, Attributes: attrs, Prefilter: filters.shouldSkip}
	}
	findings.startScan(runtime)
	if file, ok := runtime.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		runtime.Logger().Info("waiting for stdin; pipe or redirect input, or press Ctrl-C to cancel")
	}
	summary, scanErr := runner.Scan(runtime.Context, source, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("failed scan input from stdin", "error", scanErr)
	}

	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}

// cancellableStdin lets the CLI finish an interrupted scan even when the OS
// cannot interrupt a blocked stdin Read. The copying goroutine owns its buffer;
// it may remain blocked until input arrives or the process exits. Keep this
// bridge at the CLI boundary: SDK sources leave reader ownership to callers.
func cancellableStdin(ctx context.Context, content io.Reader) (io.Reader, func()) {
	reader, writer := io.Pipe()
	stop := context.AfterFunc(ctx, func() { _ = writer.CloseWithError(ctx.Err()) })
	go func() {
		err := ctx.Err()
		if err == nil {
			_, err = io.Copy(writer, content)
		}
		_ = writer.CloseWithError(err)
	}()
	return reader, func() {
		stop()
		_ = reader.Close()
	}
}

func newStdinSource(content io.Reader, attrs map[string]string, shouldSkip sources.PrefilterFunc) sources.Source {
	return &sources.Reader{
		Content:    content,
		Attributes: attrs,
		Prefilter:  shouldSkip,
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
