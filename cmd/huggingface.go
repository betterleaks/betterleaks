package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/huggingface"
)

type HuggingFaceCmd struct {
	ScanFlags           `embed:""`
	Token               string   `help:"Hugging Face access token (or set HUGGINGFACE_TOKEN/HF_TOKEN)."`
	Include             []string `help:"Resource types to scan: repos, discussions, prs, buckets."`
	Exclude             []string `help:"Resource types to skip."`
	ExcludeRepo         []string `name:"exclude-repo" help:"Glob patterns to exclude repositories by owner/name."`
	LogOpts             string   `name:"log-opts" help:"Git log options passed to each repository scan."`
	MaxBucketObjectSize int64    `name:"max-bucket-object-size" help:"Skip bucket objects larger than this many bytes (0 = 250 MiB)."`
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
	workers := resolveWorkerPlan(options.Jobs, providerWorkerProfile)
	runner := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, "", scan.WithWorkers(workers.Scanner))

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
		ShouldSkip:          runner.SkipFunc(),
		MaxArchiveDepth:     options.MaxArchiveDepth,
		Workers:             workers.Source,
		LogOpts:             options.LogOpts,
		MaxBucketObjectSize: options.MaxBucketObjectSize,
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor)

	summary, scanErr := runner.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}
