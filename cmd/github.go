package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/github"
)

type GitHubCmd struct {
	ScanFlags       `embed:""`
	Token           string   `group:"source" help:"GitHub personal access token (or set GITHUB_TOKEN)."`
	Include         []string `group:"source" help:"Resource types to scan: repos, forks, prs, pr-comments, issues, issue-comments, actions, action-artifacts, discussions, releases, release-assets, gists."`
	Exclude         []string `group:"source" help:"Resource types to skip."`
	ExcludeRepo     []string `group:"source" name:"exclude-repo" help:"Glob patterns to exclude repositories."`
	LogOpts         string   `group:"source" name:"log-opts" help:"Git log options passed to each repository scan."`
	ActionsWorkflow []string `group:"source" name:"actions-workflow" help:"Only scan runs from these workflow files."`
	Since           string   `group:"source" help:"Only scan API items created after this date (YYYY-MM-DD or RFC3339)."`
	Until           string   `group:"source" help:"Only scan API items created before this date (YYYY-MM-DD or RFC3339)."`
	TargetURL       string   `arg:"" name:"target-url" help:"GitHub repository, organization, or resource URL."`
}

func (cmd *GitHubCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runGitHub(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runGitHub(runtime *commandRuntime, globals *GlobalFlags, options *GitHubCmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config(runtime)
	filters := loadScanFilters(runtime, cfg, options.IgnoreFile, "")
	runner := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))

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
			runtime.fatal("invalid --since value; use YYYY-MM-DD or RFC3339", "error", err)
		}
	}
	if s := options.Until; s != "" {
		until, err = parseDateFlag(s)
		if err != nil {
			runtime.fatal("invalid --until value; use YYYY-MM-DD or RFC3339", "error", err)
		}
	}

	src := &github.Source{
		Logger:          runtime.Logger(),
		Token:           token,
		URL:             targetURL,
		Include:         options.Include,
		Exclude:         options.Exclude,
		ExcludeRepos:    options.ExcludeRepo,
		ShouldSkip:      filters.shouldSkip,
		MaxArchiveDepth: options.MaxArchiveDepth,
		Workers:         resolveSourceWorkers(options.Jobs, defaultSourceWorkers),
		LogOpts:         options.LogOpts,
		Actions: github.ActionsOptions{
			Workflows: options.ActionsWorkflow,
		},
		DateRangeOpts: github.DateRangeOptions{
			Since: since,
			Until: until,
		},
	}

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor)

	summary, scanErr := runner.Scan(runtime.Context, src, findings.Add)
	if scanErr != nil {
		runtime.Logger().Error("scan error", "error", scanErr)
	}
	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, scanErr)
}

// parseDateFlag parses a date string as either YYYY-MM-DD or RFC3339.
func parseDateFlag(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
