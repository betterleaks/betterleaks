package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

type URLCmd struct {
	ScanFlags `embed:""`
	URL       string `arg:"" help:"HTTP(S) URL to download and scan (no crawling)."`
}

func (cmd *URLCmd) Run(cli *CLI, runtime *commandRuntime) error {
	start := time.Now()
	initConfig(runtime, &cli.GlobalFlags, &cmd.ScanFlags, ".")
	initDiagnostics(runtime, &cmd.ScanFlags)

	cfg := Config(runtime)
	filters := loadScanFilters(runtime, cfg, cmd.IgnoreFile, "")
	runner := newScanPipeline(runtime, &cli.GlobalFlags, &cmd.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))
	findings := mustNewFindingCollector(runtime, &cmd.ScanFlags, cli.NoColor)

	src := &sources.URL{
		URL:             cmd.URL,
		Logger:          runtime.Logger(),
		ShouldSkip:      filters.shouldSkip,
		MaxArchiveDepth: cmd.MaxArchiveDepth,
		MaxSize:         int64(cmd.MaxTargetMegabytes) * 1_000_000,
	}

	summary, err := runner.Scan(runtime.Context, src, findings.Add)
	if err != nil {
		runtime.Logger().Error("failed to scan URL", "error", err)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, cmd.ExitCode, start, err)
	return nil
}
