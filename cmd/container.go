package cmd

import (
	"errors"
	"time"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/container"
)

type ContainerCmd struct {
	ScanFlags         `embed:""`
	Images            []string `arg:"" optional:"" name:"image" help:"Registry image references (all platforms and layers by default)."`
	Archive           []string `group:"source" name:"archive" sep:"none" help:"Docker save or OCI image archive (repeatable; compression detected automatically)."`
	OCILayout         []string `group:"source" name:"oci-layout" sep:"none" help:"OCI image layout directory (repeatable)."`
	Daemon            string   `group:"source" placeholder:"RUNTIME" help:"Export local images through the Docker or Podman API: docker or podman (no CLI required)."`
	DaemonHost        string   `group:"source" name:"daemon-host" placeholder:"URL" help:"Engine endpoint: unix:///path/to/socket, http://host:port, or https://host:port."`
	Platform          []string `group:"source" sep:"none" help:"Select os/architecture[/variant] (repeatable; default: all platforms)."`
	Anonymous         bool     `group:"source" help:"Ignore all registry credentials, including credential helpers."`
	CredentialHelpers bool     `group:"source" name:"credential-helpers" help:"Allow executing configured Docker credential helpers for registry authentication."`
	PlainHTTP         bool     `group:"source" name:"plain-http" help:"Use unencrypted HTTP for registry access."`
	MaxFileSize       sizeFlag `group:"source" name:"max-file-size" help:"Maximum layer file size (e.g. 250MiB; 0 = unlimited). Exceeding it marks the scan incomplete."`
	MaxArchiveSize    sizeFlag `group:"source" name:"max-archive-size" help:"Maximum expanded outer archive bytes, including headers and padding (0 = 20 GiB)."`
	MaxArchiveDepth   int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Scan nested archives inside layer files up to this depth."`
}

func (c *ContainerCmd) source() *container.Source {
	return &container.Source{
		Images:            c.Images,
		Archives:          c.Archive,
		Layouts:           c.OCILayout,
		Platforms:         c.Platform,
		Daemon:            c.Daemon,
		DaemonHost:        c.DaemonHost,
		Anonymous:         c.Anonymous,
		CredentialHelpers: c.CredentialHelpers,
		PlainHTTP:         c.PlainHTTP,
		MaxFileSize:       int64(c.MaxFileSize),
		MaxArchiveSize:    int64(c.MaxArchiveSize),
		MaxArchiveDepth:   c.MaxArchiveDepth,
	}
}

func (c *ContainerCmd) Validate(ctx *kong.Context) error {
	if err := c.ScanFlags.Validate(); err != nil {
		return err
	}
	if flagWasSet(ctx, "daemon") && c.Daemon == "" {
		return errors.New("--daemon requires docker or podman")
	}
	if flagWasSet(ctx, "daemon-host") && c.DaemonHost == "" {
		return errors.New("--daemon-host requires an engine endpoint")
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
	if c.Daemon != "" {
		for i := range targets {
			targets[i] = "daemon:" + c.Daemon + ":" + targets[i]
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
