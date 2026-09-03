package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks/v2/detect"
	"github.com/betterleaks/betterleaks/v2/sources"
)

type S3Cmd struct {
	ScanFlags     `embed:""`
	Region        string `help:"AWS region (required for some non-AWS endpoints; auto-probed for AWS)."`
	Anonymous     bool   `help:"Do not sign requests; ignore AWS credential environment variables and flags."`
	AccessKey     string `name:"access-key" help:"AWS access key (overrides AWS_ACCESS_KEY_ID)."`
	SecretKey     string `name:"secret-key" help:"AWS secret key (overrides AWS_SECRET_ACCESS_KEY)."`
	SessionToken  string `name:"session-token" help:"AWS session token (overrides AWS_SESSION_TOKEN)."`
	MaxObjectSize int64  `name:"max-object-size" help:"Skip objects larger than this many bytes (0 = 250 MiB)."`
	URL           string `arg:"" help:"S3 or S3-compatible bucket URL."`
}

func (cmd *S3Cmd) Run(cli *CLI, runtime *commandRuntime) error {
	runS3(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runS3(runtime *commandRuntime, globals *GlobalFlags, options *S3Cmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config(runtime)
	jobs := resolveJobPlan(options.Jobs, objectJobProfile)
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, "", detect.WithJobs(jobs.Detector))

	src := &sources.S3{
		Logger:          runtime.Logger(),
		URL:             options.URL,
		Region:          options.Region,
		Anonymous:       options.Anonymous,
		AccessKey:       options.AccessKey,
		SecretKey:       options.SecretKey,
		SessionToken:    options.SessionToken,
		MaxObjectSize:   options.MaxObjectSize,
		Jobs:            jobs.Source,
		ShouldSkip:      detector.SkipFunc(),
		MaxArchiveDepth: options.MaxArchiveDepth,
	}

	if err := src.Validate(); err != nil {
		runtime.fatal("invalid S3 configuration", "error", err)
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor)

	summary, scanErr := detector.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, detector.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}
