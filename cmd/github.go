package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

type GitHubCmd struct {
	ScanFlags       `embed:""`
	Token           string   `help:"GitHub personal access token (or set GITHUB_TOKEN)."`
	Include         []string `help:"Resource types to scan: repos, forks, prs, pr-comments, issues, issue-comments, actions, action-artifacts, discussions, releases, release-assets, gists."`
	Exclude         []string `help:"Resource types to skip."`
	ExcludeRepo     []string `name:"exclude-repo" help:"Glob patterns to exclude repositories."`
	LogOpts         string   `name:"log-opts" help:"Git log options passed to each repository scan."`
	ActionsWorkflow []string `name:"actions-workflow" help:"Only scan runs from these workflow files."`
	Since           string   `help:"Only scan API items created after this date (YYYY-MM-DD or RFC3339)."`
	Until           string   `help:"Only scan API items created before this date (YYYY-MM-DD or RFC3339)."`
	TargetURL       string   `arg:"" name:"target-url" help:"GitHub repository, organization, or resource URL."`
}

func (cmd *GitHubCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runGitHub(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runGitHub(runtime *commandRuntime, globals *GlobalFlags, options *GitHubCmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(&options.ScanFlags)

	cfg := Config()
	jobs := resolveJobPlan(options.Jobs, providerJobProfile)
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, "", detect.WithJobs(jobs.Detector))

	targetURL := options.TargetURL

	// Resolve token: flag > env
	token := options.Token
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	// Parse date range flags.
	var since, until time.Time
	var err error
	if s := options.Since; s != "" {
		since, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --since value; use YYYY-MM-DD or RFC3339")
		}
	}
	if s := options.Until; s != "" {
		until, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --until value; use YYYY-MM-DD or RFC3339")
		}
	}

	src := &sources.GitHub{
		Token:           token,
		URL:             targetURL,
		Include:         options.Include,
		Exclude:         options.Exclude,
		ExcludeRepos:    options.ExcludeRepo,
		ShouldSkip:      detector.SkipFunc(),
		MaxArchiveDepth: options.MaxArchiveDepth,
		Jobs:            jobs.Source,
		LogOpts:         options.LogOpts,
		Actions: sources.ActionsOptions{
			Workflows: options.ActionsWorkflow,
		},
		DateRangeOpts: sources.DateRangeOptions{
			Since: since,
			Until: until,
		},
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid GitHub configuration")
	}

	findings := mustNewFindingCollector(&options.ScanFlags, globals.NoColor, runtime.stdout)

	summary, scanErr := detector.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		logging.Error().Err(scanErr).Msg("scan error")
	}
	findingSummaryAndExit(runtime, summary, detector.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}

// parseDateFlag parses a date string as either YYYY-MM-DD or RFC3339.
func parseDateFlag(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
