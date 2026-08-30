package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

type GitLabCmd struct {
	ScanFlags        `embed:""`
	Token            string   `help:"GitLab personal access token (or set GITLAB_TOKEN)."`
	BaseURL          string   `name:"base-url" help:"Site base URL for self-hosted instances."`
	Include          []string `help:"Resource types to scan: repos, forks, mrs, mr-comments, issues, issue-comments, snippets, releases, release-assets, ci-jobs, ci-artifacts."`
	Exclude          []string `help:"Resource types to skip."`
	ExcludeRepo      []string `name:"exclude-repo" help:"Glob patterns to exclude projects by full path."`
	IncludeSubgroups bool     `name:"include-subgroups" default:"true" help:"When scanning a group, recurse into subgroups."`
	AllGroups        bool     `name:"all-groups" help:"Enumerate every group visible to the token."`
	LogOpts          string   `name:"log-opts" help:"Git log options passed to each project scan."`
	Since            string   `help:"Only scan API items created after this date (YYYY-MM-DD or RFC3339)."`
	Until            string   `help:"Only scan API items created before this date (YYYY-MM-DD or RFC3339)."`
	TargetURL        string   `arg:"" name:"target-url" help:"GitLab project, group, or resource URL."`
}

func (cmd *GitLabCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runGitLab(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runGitLab(runtime *commandRuntime, globals *GlobalFlags, options *GitLabCmd) {
	start := time.Now()

	initConfig(runtime, globals, &options.ScanFlags, ".")
	initDiagnostics(&options.ScanFlags)

	cfg := Config()
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, ".")
	jobs := resolveJobPlan(options.Jobs, providerJobProfile)
	detector.Jobs = jobs.Detector

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
			logging.Fatal().Err(err).Msg("invalid --since value; use YYYY-MM-DD or RFC3339")
		}
	}
	if s := options.Until; s != "" {
		until, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --until value; use YYYY-MM-DD or RFC3339")
		}
	}

	src := &sources.GitLab{
		Token:            token,
		URL:              targetURL,
		BaseURL:          options.BaseURL,
		Include:          options.Include,
		Exclude:          options.Exclude,
		ExcludeRepos:     options.ExcludeRepo,
		AllGroups:        options.AllGroups,
		IncludeSubgroups: options.IncludeSubgroups,
		ShouldSkip:       detector.SkipFunc(),
		MaxArchiveDepth:  options.MaxArchiveDepth,
		Jobs:             jobs.Source,
		LogOpts:          options.LogOpts,
		DateRangeOpts: sources.DateRangeOptions{
			Since: since,
			Until: until,
		},
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid GitLab configuration")
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
			msg:  fmt.Sprintf("%d error(s) during GitLab scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(runtime, detector, findings, options.ExitCode, start, scanErr)
}
