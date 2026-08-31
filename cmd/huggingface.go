package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
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
	initDiagnostics(&options.ScanFlags)

	cfg := Config()
	jobs := resolveJobPlan(options.Jobs, providerJobProfile)
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, "", detect.WithJobs(jobs.Detector))

	token := options.Token
	if token == "" {
		token = os.Getenv("HUGGINGFACE_TOKEN")
	}
	if token == "" {
		token = os.Getenv("HF_TOKEN")
	}

	src := &sources.HuggingFace{
		Token:               token,
		URL:                 options.TargetURL,
		Include:             options.Include,
		Exclude:             options.Exclude,
		ExcludeRepos:        options.ExcludeRepo,
		ShouldSkip:          detector.SkipFunc(),
		MaxArchiveDepth:     options.MaxArchiveDepth,
		Jobs:                jobs.Source,
		LogOpts:             options.LogOpts,
		MaxBucketObjectSize: options.MaxBucketObjectSize,
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid Hugging Face configuration")
	}

	findings := mustNewFindingCollector(&options.ScanFlags, globals.NoColor, runtime.stdout)

	summary, scanErr := detector.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		logging.Error().Err(scanErr).Msg("scan error")
	}
	findingSummaryAndExit(runtime, summary, detector.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}
