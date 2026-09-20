package cmd

import (
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/gitlab"
)

type GitLabCmd struct {
	ScanFlags        `embed:""`
	Token            string   `group:"source" help:"GitLab personal access token (or set GITLAB_TOKEN)."`
	BaseURL          string   `group:"source" name:"base-url" help:"Site base URL for self-hosted instances."`
	Include          []string `group:"source" help:"Resource types to scan: repos, forks, mrs, mr-comments, issues, issue-comments, snippets, releases, release-assets, ci-jobs, ci-artifacts."`
	Exclude          []string `group:"source" help:"Resource types to skip."`
	ExcludeRepo      []string `group:"source" name:"exclude-repo" help:"Glob patterns to exclude projects by full path."`
	IncludeSubgroups bool     `group:"source" name:"include-subgroups" default:"true" help:"When scanning a group, recurse into subgroups."`
	AllGroups        bool     `group:"source" name:"all-groups" help:"Enumerate every group visible to the token."`
	LogOpts          string   `group:"source" name:"log-opts" help:"Git log options passed to each project scan."`
	Since            string   `group:"source" help:"Only scan API items created after this date (YYYY-MM-DD or RFC3339)."`
	Until            string   `group:"source" help:"Only scan API items created before this date (YYYY-MM-DD or RFC3339)."`
	TargetURL        string   `arg:"" name:"target-url" help:"GitLab project, group, or resource URL."`
}

func (cmd *GitLabCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runGitLab(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runGitLab(runtime *commandRuntime, globals *GlobalFlags, options *GitLabCmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config(runtime)
	filters := loadScanFilters(runtime, cfg, options.IgnoreFile, "")
	runner := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))

	targetURL := options.TargetURL

	token := options.Token
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}

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

	src := &gitlab.Source{
		Logger:           runtime.Logger(),
		Token:            token,
		URL:              targetURL,
		BaseURL:          options.BaseURL,
		Include:          options.Include,
		Exclude:          options.Exclude,
		ExcludeRepos:     options.ExcludeRepo,
		AllGroups:        options.AllGroups,
		IncludeSubgroups: options.IncludeSubgroups,
		ShouldSkip:       filters.shouldSkip,
		MaxArchiveDepth:  options.MaxArchiveDepth,
		Workers:          resolveSourceWorkers(options.Jobs, defaultSourceWorkers),
		LogOpts:          options.LogOpts,
		DateRangeOpts: gitlab.DateRangeOptions{
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
