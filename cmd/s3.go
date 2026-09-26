package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/s3"
)

type S3Cmd struct {
	ScanFlags     `embed:""`
	Region        string `group:"source" help:"AWS region (required for some non-AWS endpoints; auto-probed for AWS)."`
	Anonymous     bool   `group:"source" help:"Do not sign requests; ignore AWS credential environment variables and flags."`
	AccessKey     string `group:"source" name:"access-key" help:"AWS access key (overrides AWS_ACCESS_KEY_ID)."`
	SecretKey     string `group:"source" name:"secret-key" help:"AWS secret key (overrides AWS_SECRET_ACCESS_KEY)."`
	SessionToken  string `group:"source" name:"session-token" help:"AWS session token (overrides AWS_SESSION_TOKEN)."`
	MaxObjectSize int64  `group:"source" name:"max-object-size" help:"Skip objects larger than this many bytes (0 = 250 MiB)."`
	URL           string `arg:"" help:"S3 or S3-compatible bucket URL."`
}

func (cmd *S3Cmd) Run(cli *CLI, runtime *commandRuntime) error {
	runS3(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runS3(runtime *commandRuntime, globals *GlobalFlags, options *S3Cmd) {
	start := time.Now()

	cfg := initConfig(runtime, globals, &options.ScanFlags)
	initDiagnostics(runtime, &options.ScanFlags)

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

	src := &s3.Source{
		Logger:          runtime.Logger(),
		URL:             options.URL,
		Region:          options.Region,
		Anonymous:       options.Anonymous,
		AccessKey:       options.AccessKey,
		SecretKey:       options.SecretKey,
		SessionToken:    options.SessionToken,
		MaxObjectSize:   options.MaxObjectSize,
		ShouldSkip:      filters.shouldSkip,
		MaxArchiveDepth: options.MaxArchiveDepth,
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "s3", options.URL)

	findings.startScan(runtime)
	summary, scanErr := runner.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}
