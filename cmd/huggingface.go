package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/huggingface"
)

type HuggingFaceCmd struct {
	ScanFlags           `embed:""`
	Token               string   `group:"source" help:"Hugging Face access token (or set HUGGINGFACE_TOKEN/HF_TOKEN)."`
	Include             []string `group:"source" help:"Resource types to scan: repos, discussions, prs, buckets."`
	Exclude             []string `group:"source" help:"Resource types to skip."`
	ExcludeRepo         []string `group:"source" name:"exclude-repo" help:"Glob patterns to exclude repositories by owner/name."`
	LogOpts             string   `group:"source" name:"log-opts" help:"Git log options passed to each repository scan."`
	MaxBucketObjectSize int64    `group:"source" name:"max-bucket-object-size" help:"Skip bucket objects larger than this many bytes (0 = 250 MiB)."`
	TargetURL           string   `arg:"" name:"target-url" help:"Hugging Face repository, owner, or bucket URL."`
}

func (cmd *HuggingFaceCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runHuggingFace(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runHuggingFace(runtime *commandRuntime, globals *GlobalFlags, options *HuggingFaceCmd) {
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

	token := options.Token
	if token == "" {
		token = os.Getenv("HUGGINGFACE_TOKEN")
	}
	if token == "" {
		token = os.Getenv("HF_TOKEN")
	}

	src := &huggingface.Source{
		Logger:              runtime.Logger(),
		Token:               token,
		URL:                 options.TargetURL,
		Include:             options.Include,
		Exclude:             options.Exclude,
		ExcludeRepos:        options.ExcludeRepo,
		ShouldSkip:          filters.shouldSkip,
		MaxArchiveDepth:     options.MaxArchiveDepth,
		LogOpts:             options.LogOpts,
		MaxBucketObjectSize: options.MaxBucketObjectSize,
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "huggingface", options.TargetURL)

	findings.startScan(runtime)
	summary, scanErr := runner.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}
