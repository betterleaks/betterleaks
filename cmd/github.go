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
	githubCmd.Flags().StringSlice("include", nil,
		"resource types to scan: repos (default), forks, prs, pr-comments, "+
			"issues, issue-comments, actions, action-artifacts, discussions, releases, release-assets, gists")
	githubCmd.Flags().StringSlice("exclude", nil,
		"resource types to skip: repos, forks, prs, pr-comments, "+
			"issues, issue-comments, actions, action-artifacts, discussions, releases, release-assets, gists")
	githubCmd.Flags().StringSlice("exclude-repo", nil, "glob patterns to exclude repos")
	githubCmd.Flags().Int("git-workers", 0, "parallel git workers per repo (0 = single process)")
	githubCmd.Flags().String("log-opts", "", "git log options passed to each repo scan")

	// Actions scanning
	githubCmd.Flags().StringSlice("actions-workflow", nil, "only scan runs from these workflow files (e.g. ci.yml)")

	// Date range filtering (applies to issues, PRs, comments, and action runs)
	githubCmd.Flags().String("since", "", "only scan API items created after this date (YYYY-MM-DD or RFC3339)")
	githubCmd.Flags().String("until", "", "only scan API items created before this date (YYYY-MM-DD or RFC3339)")
}

var githubCmd = &cobra.Command{
	Use:   "github <target-url> [flags]",
	Short: "scan GitHub repositories and resources for secrets",
	Example: `  # Scan a repository's git history
  betterleaks github https://github.com/owner/repo

  # Scan a pull request
  betterleaks github https://github.com/owner/repo/pull/113

  # Scan all repos under an organization
  betterleaks github https://github.com/myorg

  # Scan repos plus issues and PRs
  betterleaks github --include=issues,prs https://github.com/owner/repo

  # Scan only issues and comments, skip repo git history
  betterleaks github --include=issues,issue-comments --exclude=repos https://github.com/owner/repo`,
	Args: cobra.ExactArgs(1),
	Run:  runGitHub,
}

func runGitHub(cmd *cobra.Command, args []string) {
	start := time.Now()

	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, ".")

	targetURL := args[0]

	// Resolve token: flag > env
	token := mustGetStringFlag(cmd, "token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	include, _ := cmd.Flags().GetStringSlice("include")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")

	// Parse date range flags.
	var since, until time.Time
	var err error
	if s := mustGetStringFlag(cmd, "since"); s != "" {
		since, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --since value; use YYYY-MM-DD or RFC3339")
		}
	}
	if s := mustGetStringFlag(cmd, "until"); s != "" {
		until, err = parseDateFlag(s)
		if err != nil {
			logging.Fatal().Err(err).Msg("invalid --until value; use YYYY-MM-DD or RFC3339")
		}
	}

	actionsWorkflows, _ := cmd.Flags().GetStringSlice("actions-workflow")
	excludeRepos, _ := cmd.Flags().GetStringSlice("exclude-repo")

	src := &sources.GitHub{
		Token:           token,
		URL:             targetURL,
		Include:         include,
		Exclude:         exclude,
		ExcludeRepos:    excludeRepos,
		ShouldSkip:      detector.SkipFunc(),
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
		Workers:         mustGetIntFlag(cmd, "git-workers"),
		LogOpts:         mustGetStringFlag(cmd, "log-opts"),
		Actions: sources.ActionsOptions{
			Workflows: actionsWorkflows,
		},
		DateRangeOpts: sources.DateRangeOptions{
			Since: since,
			Until: until,
		},
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid GitHub configuration")
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

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) during GitHub scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(detector, findings, exitCode, start, scanErr)
}

// parseDateFlag parses a date string as either YYYY-MM-DD or RFC3339.
func parseDateFlag(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}
