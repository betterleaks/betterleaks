package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/container"
)

type ContainerCmd struct {
	ScanFlags       `embed:""`
	Images          []string `arg:"" optional:"" name:"image" help:"Registry image references (all platforms and layers by default)."`
	Archive         []string `group:"source" name:"archive" sep:"none" help:"Docker save or OCI image archive (repeatable; compression detected automatically)."`
	OCILayout       []string `group:"source" name:"oci-layout" sep:"none" help:"OCI image layout directory (repeatable)."`
	Daemon          bool     `group:"source" help:"Export image references from the local Docker daemon using docker image save."`
	Platform        []string `group:"source" sep:"none" help:"Select os/architecture[/variant] (repeatable; default: all platforms)."`
	Anonymous       bool     `group:"source" help:"Ignore Docker registry credentials and credential helpers."`
	PlainHTTP       bool     `group:"source" name:"plain-http" help:"Use unencrypted HTTP for registry access."`
	MaxFileSize     sizeFlag `group:"source" name:"max-file-size" help:"Maximum layer file size (e.g. 250MiB; 0 = unlimited). Exceeding it marks the scan incomplete."`
	MaxArchiveSize  sizeFlag `group:"source" name:"max-archive-size" help:"Maximum expanded outer image archive size (0 = 20 GiB)."`
	MaxArchiveDepth int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Scan nested archives inside layer files up to this depth."`
}

func (c *ContainerCmd) source() *container.Source {
	return &container.Source{
		Images:          c.Images,
		Archives:        c.Archive,
		Layouts:         c.OCILayout,
		Platforms:       c.Platform,
		Daemon:          c.Daemon,
		Anonymous:       c.Anonymous,
		PlainHTTP:       c.PlainHTTP,
		MaxFileSize:     int64(c.MaxFileSize),
		MaxArchiveSize:  int64(c.MaxArchiveSize),
		MaxArchiveDepth: c.MaxArchiveDepth,
	}
}

func (c *ContainerCmd) Validate() error {
	if err := c.ScanFlags.Validate(); err != nil {
		return err
	}
	return c.source().Validate()
}

func (c *ContainerCmd) Run(cli *CLI, runtime *commandRuntime) error {
	start := time.Now()
	cfg := initConfig(runtime, &cli.GlobalFlags, &c.ScanFlags)
	initDiagnostics(runtime, &c.ScanFlags)
	filters, err := loadScanFilters(runtime, cfg, c.IgnoreFile, "")
	if err != nil {
		return err
	}
	runner, err := newScanPipeline(runtime, &cli.GlobalFlags, &c.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))
	if err != nil {
		return err
	}
	src := c.source()
	src.Logger, src.Prefilter = runtime.Logger(), filters.shouldSkip
	targets := append([]string(nil), c.Images...)
	if c.Daemon {
		for i := range targets {
			targets[i] = "daemon:" + targets[i]
		}
	}
	for _, p := range c.Archive {
		targets = append(targets, "archive:"+p)
	}
	for _, p := range c.OCILayout {
		targets = append(targets, "oci:"+p)
	}
	findings := mustNewFindingCollector(runtime, &c.ScanFlags, cli.NoColor, start, cfg, "container", targets...)
	findings.startScan(runtime)
	summary, scanErr := runner.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("container scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, c.ExitCode, start, scanErr)
	return nil
}
