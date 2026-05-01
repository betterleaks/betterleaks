package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(githubCmd)
	githubCmd.Flags().String("token", "", "GitHub personal access token (or set GITHUB_TOKEN)")
	githubCmd.Flags().StringSlice("org", nil, "GitHub organization(s) to scan")
	githubCmd.Flags().StringSlice("user", nil, "GitHub user(s) to scan")
	githubCmd.Flags().StringSlice("repo", nil, "specific repos to scan (owner/repo)")
	githubCmd.Flags().StringSlice("exclude-repo", nil, "glob patterns to exclude repos")
	githubCmd.Flags().Bool("exclude-forks", false, "exclude forked repositories")
	githubCmd.Flags().Bool("no-git", false, "skip repository git history scanning and only scan selected GitHub API resources")
	githubCmd.Flags().Int("git-workers", 0, "parallel git workers per repo (0 = single process)")
	githubCmd.Flags().String("log-opts", "", "git log options passed to each repo scan")
	githubCmd.Flags().String("base-url", "", "GitHub Enterprise base URL")

	// Actions scanning
	githubCmd.Flags().Bool("actions", false, "scan GitHub Actions workflow run logs")
	githubCmd.Flags().StringSlice("actions-workflow", nil, "only scan runs from these workflow files (e.g. ci.yml)")
	githubCmd.Flags().Duration("actions-max-age", 0, "max age of workflow runs to scan (e.g. 720h for 30 days)")
	githubCmd.Flags().Int("actions-max-runs", 50, "max workflow runs to scan per repo")
	githubCmd.Flags().Bool("actions-artifacts", false, "also download and scan workflow artifacts")

	// Issue and PR scanning
	githubCmd.Flags().Bool("issues", false, "scan GitHub Issues (titles and bodies)")
	githubCmd.Flags().Bool("prs", false, "scan GitHub Pull Requests (titles and bodies)")
	githubCmd.Flags().Bool("comments", false, "scan GitHub Issue and PR comments")
	githubCmd.Flags().Int("issues-max", 100, "maximum number of recent issues/PRs to fetch per repo (0 = no limit)")
	githubCmd.Flags().Int("comments-max", 50, "maximum number of comments to fetch per issue/PR (0 = no limit)")

	// Date range filtering (applies to issues, PRs, comments, and actions)
	githubCmd.Flags().String("since", "", "only scan items pulled from the GitHub API (issues, PRs, actions, etc) created after this date (YYYY-MM-DD or RFC3339)")
	githubCmd.Flags().String("until", "", "only scan items pulled from the GitHub API (issues, PRs, actions, etc) created before this date (YYYY-MM-DD or RFC3339)")

	// Full GitHub coverage
	githubCmd.Flags().Bool("discussions", false, "scan GitHub Discussions (titles, bodies, and comments)")
	githubCmd.Flags().Bool("releases", false, "scan GitHub Releases (titles, bodies, and assets)")
	githubCmd.Flags().Bool("no-release-artifacts", false, "disable downloading and scanning release assets when --releases is set")
	githubCmd.Flags().Bool("gists", false, "scan GitHub Gists file contents (requires --user)")

	// Single resource URL mode
	githubCmd.Flags().String("resource-url", "", "scan a single GitHub resource URL (issue, PR, discussion, release, action run, or gist)")
}

var githubCmd = &cobra.Command{
	Use:   "github [flags]",
	Short: "scan GitHub repositories for secrets",
	Run:   runGitHub,
}

func runGitHub(cmd *cobra.Command, args []string) {
	start := time.Now()

	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, ".")

	// Resolve token: flag > env
	token := mustGetStringFlag(cmd, "token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	scanActions := mustGetBoolFlag(cmd, "actions")
	scanIssues := mustGetBoolFlag(cmd, "issues")
	scanPRs := mustGetBoolFlag(cmd, "prs")
	scanComments := mustGetBoolFlag(cmd, "comments")
	scanDiscussions := mustGetBoolFlag(cmd, "discussions")
	scanReleases := mustGetBoolFlag(cmd, "releases")
	scanGists := mustGetBoolFlag(cmd, "gists")
	skipRepoGit := mustGetBoolFlag(cmd, "no-git")
	resourceURL := mustGetStringFlag(cmd, "resource-url")

	if token == "" && scanActions {
		logging.Fatal().Msg("--actions requires a token (--token or GITHUB_TOKEN) with actions:read scope")
	}
	if token == "" && (scanIssues || scanPRs || scanComments) {
		logging.Fatal().Msg("--issues, --prs, and --comments require a token (--token or GITHUB_TOKEN); GitHub GraphQL API v4 requires authentication")
	}
	if token == "" && scanDiscussions {
		logging.Fatal().Msg("--discussions requires a token (--token or GITHUB_TOKEN); GitHub GraphQL API v4 requires authentication")
	}
	if token == "" && (scanReleases || scanGists) {
		logging.Fatal().Msg("--releases and --gists require a token (--token or GITHUB_TOKEN)")
	}
	if token == "" && resourceURL != "" {
		logging.Fatal().Msg("--resource-url requires a token (--token or GITHUB_TOKEN)")
	}

	orgs, _ := cmd.Flags().GetStringSlice("org")
	users, _ := cmd.Flags().GetStringSlice("user")
	repos, _ := cmd.Flags().GetStringSlice("repo")

	if resourceURL != "" && (len(orgs) > 0 || len(users) > 0 || len(repos) > 0) {
		logging.Fatal().Msg("--resource-url is mutually exclusive with --org, --user, and --repo")
	}
	if scanGists && len(users) == 0 && resourceURL == "" {
		logging.Fatal().Msg("--gists requires at least one --user")
	}
	if resourceURL == "" && len(orgs) == 0 && len(users) == 0 && len(repos) == 0 {
		logging.Fatal().Msg("at least one --org, --user, --repo, or --resource-url is required")
	}
	if resourceURL == "" && skipRepoGit && !(scanActions || scanIssues || scanPRs || scanComments || scanDiscussions || scanReleases || scanGists) {
		logging.Fatal().Msg("--no-git requires at least one auxiliary GitHub scan flag such as --actions, --issues, --prs, --comments, --discussions, --releases, or --gists")
	}

	excludeRepos, _ := cmd.Flags().GetStringSlice("exclude-repo")

	actionsWorkflows, _ := cmd.Flags().GetStringSlice("actions-workflow")
	actionsMaxAge, _ := cmd.Flags().GetDuration("actions-max-age")

	// Parse date range flags.
	var since, until time.Time
	if s := mustGetStringFlag(cmd, "since"); s != "" {
		var err error
		since, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --since value; use YYYY-MM-DD or RFC3339")
		}
	}
	if s := mustGetStringFlag(cmd, "until"); s != "" {
		var err error
		until, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --until value; use YYYY-MM-DD or RFC3339")
		}
	}

	// If --since is set and --actions-max-age is not, derive max-age from --since.
	if !since.IsZero() && actionsMaxAge == 0 {
		actionsMaxAge = time.Since(since)
	}

	src := &sources.GitHub{
		Token:             token,
		Repos:             repos,
		Orgs:              orgs,
		Users:             users,
		ExcludeRepos:      excludeRepos,
		ExcludeForks:      mustGetBoolFlag(cmd, "exclude-forks"),
		ShouldSkip:        detector.SkipFunc(),
		Sema:              detector.Sema,
		MaxArchiveDepth:   detector.MaxArchiveDepth,
		Workers:           mustGetIntFlag(cmd, "git-workers"),
		LogOpts:           mustGetStringFlag(cmd, "log-opts"),
		BaseURL:           mustGetStringFlag(cmd, "base-url"),
		ScanActions:       scanActions,
		ScanIssues:        scanIssues,
		ScanPRs:           scanPRs,
		ScanComments:      scanComments,
		ScanDiscussions:   scanDiscussions,
		ScanReleases:      scanReleases,
		ScanReleaseAssets: scanReleases && !mustGetBoolFlag(cmd, "no-release-artifacts"),
		ScanGists:         scanGists,
		SkipRepoGit:       skipRepoGit,
		URL:               resourceURL,
		Actions: sources.ActionsOptions{
			Workflows:     actionsWorkflows,
			MaxAge:        actionsMaxAge,
			MaxRuns:       mustGetIntFlag(cmd, "actions-max-runs"),
			ScanArtifacts: mustGetBoolFlag(cmd, "actions-artifacts"),
		},
		IssueOpts: sources.IssueOptions{
			MaxIssues:   mustGetIntFlag(cmd, "issues-max"),
			MaxComments: mustGetIntFlag(cmd, "comments-max"),
			Since:       since,
			Until:       until,
		},
	}

	exitCode := mustGetIntFlag(cmd, "exit-code")
	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	verbose := mustGetBoolFlag(cmd, "verbose")

	detector.SkipFindingAppend = true
	var findings []report.Finding
	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			logging.Error().Err(result.Err).Msg("scan error")
			continue
		}
		findings = append(findings, result.Finding)
		if verbose {
			result.Finding.Print(noColor, redact)
		}
	}

	var err error
	if n := len(scanErrs); n > 0 {
		err = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) during GitHub scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(detector, findings, exitCode, start, err)
}

// parseDateFlag parses a date string as either YYYY-MM-DD or RFC3339.
func parseDateFlag(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
