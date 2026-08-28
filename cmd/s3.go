package cmd

import (
	"fmt"
	"time"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

type S3Cmd struct {
	ScanFlags     `embed:""`
	Region        string `help:"AWS region (required for some non-AWS endpoints; auto-probed for AWS)."`
	Anonymous     bool   `help:"Do not sign requests; ignore AWS credential environment variables and flags."`
	AccessKey     string `name:"access-key" help:"AWS access key (overrides AWS_ACCESS_KEY_ID)."`
	SecretKey     string `name:"secret-key" help:"AWS secret key (overrides AWS_SECRET_ACCESS_KEY)."`
	SessionToken  string `name:"session-token" help:"AWS session token (overrides AWS_SESSION_TOKEN)."`
	MaxObjectSize int64  `name:"max-object-size" help:"Skip objects larger than this many bytes (0 = 250 MiB)."`
	Workers       int    `help:"Concurrent object fetches (0 = --source-workers or source default)."`
	URL           string `arg:"" help:"S3 or S3-compatible bucket URL."`
}

func (cmd *S3Cmd) Run(cli *CLI, runtime *commandRuntime) error {
	runS3(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runS3(runtime *commandRuntime, globals *GlobalFlags, options *S3Cmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(&options.ScanFlags)

	cfg := Config()
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, ".")
	workers := options.Workers
	if workers == 0 {
		workers = options.SourceWorkers
	}

	src := &sources.S3{
		URL:             options.URL,
		Region:          options.Region,
		Anonymous:       options.Anonymous,
		AccessKey:       options.AccessKey,
		SecretKey:       options.SecretKey,
		SessionToken:    options.SessionToken,
		MaxObjectSize:   options.MaxObjectSize,
		Workers:         workers,
		ShouldSkip:      detector.SkipFunc(),
		MaxArchiveDepth: options.MaxArchiveDepth,
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid S3 configuration")
	}

	findings := mustNewFindingCollector(&options.ScanFlags, globals.NoColor, runtime.stdout)

	var scanErrs []error
	for result := range detector.Run(runtime.Context, src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			logging.Error().Err(result.Err).Msg("scan error")
			continue
		}
		collectFinding(findings, result.Finding)
	}

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) during S3 scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(runtime, detector, findings, options.ExitCode, start, scanErr)
}
