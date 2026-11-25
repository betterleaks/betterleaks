package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/oci"
)

// OCICmd scans the OCI layout produced by a local image build.
type OCICmd struct {
	ScanFlags       `embed:""`
	Path            string   `arg:"" help:"Local OCI image layout directory (not a registry reference or tar archive)."`
	Ref             string   `help:"Select an org.opencontainers.image.ref.name from the layout index."`
	Platform        string   `help:"Select os/architecture[/variant]; default scans all image platforms."`
	MaxArchiveDepth int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Archive nesting within layer files; the image and layer envelopes do not count."`
	MaxLayerSize    sizeFlag `group:"scanning" name:"max-layer-size" default:"4GiB" help:"Maximum decompressed size per layer and logical size per file (e.g. 8GiB; 0 uses the 4GiB default)."`
}

func (cmd *OCICmd) Run(cli *CLI, runtime *commandRuntime) error {
	start := time.Now()
	cfg := initConfig(runtime, &cli.GlobalFlags, &cmd.ScanFlags)
	initDiagnostics(runtime, &cmd.ScanFlags)
	filters, err := loadScanFilters(runtime, cfg, cmd.IgnoreFile, "")
	if err != nil {
		runtime.fatal("unable to prepare scan", "error", err)
		return nil
	}
	runner, err := newScanPipeline(runtime, &cli.GlobalFlags, &cmd.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))
	if err != nil {
		runtime.fatal("unable to prepare scan", "error", err)
		return nil
	}
	findings := mustNewFindingCollector(runtime, &cmd.ScanFlags, cli.NoColor, start, cfg, "oci", cmd.Path)
	src := &oci.Layout{Path: cmd.Path, Ref: cmd.Ref, Platform: cmd.Platform, Logger: runtime.Logger(), Prefilter: filters.shouldSkip, MaxArchiveDepth: cmd.MaxArchiveDepth, MaxLayerSize: int64(cmd.MaxLayerSize)}
	findings.startScan(runtime)
	summary, err := runner.Scan(runtime.Context, src, findings.Add)
	if err != nil {
		runtime.Logger().Error("failed to scan OCI layout", "error", err)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, cmd.ExitCode, start, err)
	return nil
}
