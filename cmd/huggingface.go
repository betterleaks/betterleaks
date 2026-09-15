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
	MaxBucketObjectSize sizeFlag `group:"source" name:"max-bucket-object-size" placeholder:"SIZE" help:"Skip bucket objects larger than this size (e.g. 250MiB, 1GB; 0 = 250 MiB default)."`
	TargetURL           string   `arg:"" name:"target-url" help:"Hugging Face repository, owner, or bucket URL."`
}

func (cmd *HuggingFaceCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runHuggingFace(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runHuggingFace(runtime *commandRuntime, globals *GlobalFlags, options *HuggingFaceCmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config(runtime)
	filters := loadScanFilters(runtime, cfg, options.IgnoreFile, "")
	runner := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))

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
		Workers:             resolveSourceWorkers(options.Jobs, defaultSourceWorkers),
		LogOpts:             options.LogOpts,
		MaxBucketObjectSize: int64(options.MaxBucketObjectSize),
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor)

	summary, scanErr := runner.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}
