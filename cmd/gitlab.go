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
	rootCmd.AddCommand(gitlabCmd)
	gitlabCmd.Flags().String("token", "", "GitLab personal access token (or set GITLAB_TOKEN)")
	gitlabCmd.Flags().String("base-url", "", "site base URL for self-hosted instances (e.g. https://gitlab.example.com/)")
	gitlabCmd.Flags().StringSlice("include", nil,
		"resource types to scan: repos (default), forks, mrs, mr-comments, "+
			"issues, issue-comments, snippets, releases, release-assets, ci-jobs, ci-artifacts")
	gitlabCmd.Flags().StringSlice("exclude", nil,
		"resource types to skip: repos, forks, mrs, mr-comments, "+
			"issues, issue-comments, snippets, releases, release-assets, ci-jobs, ci-artifacts")
	gitlabCmd.Flags().StringSlice("exclude-repo", nil, "glob patterns to exclude projects by full path (e.g. 'group/test-*')")
	gitlabCmd.Flags().Bool("include-subgroups", true, "when scanning a group, recurse into subgroups")
	gitlabCmd.Flags().Bool("all-groups", false, "enumerate every group visible to the token (instance-wide)")
	gitlabCmd.Flags().Int("git-workers", 0, "parallel git workers per project (0 = single process)")
	gitlabCmd.Flags().String("log-opts", "", "git log options passed to each project scan")

	gitlabCmd.Flags().String("since", "", "only scan API items created after this date (YYYY-MM-DD or RFC3339)")
	gitlabCmd.Flags().String("until", "", "only scan API items created before this date (YYYY-MM-DD or RFC3339)")
}

var gitlabCmd = &cobra.Command{
	Use:   "gitlab <target-url> [flags]",
	Short: "scan GitLab projects and resources for secrets",
	Example: `  # Scan a project's git history
  betterleaks gitlab https://gitlab.com/group/project

  # Scan a merge request
  betterleaks gitlab https://gitlab.com/group/project/-/merge_requests/42

  # Scan all projects under a group (recursing into subgroups by default)
  betterleaks gitlab https://gitlab.com/mygroup

  # Scan projects plus issues and MRs
  betterleaks gitlab --include=issues,mrs https://gitlab.com/group/project

  # Scan a self-hosted instance
  betterleaks gitlab --base-url=https://gitlab.example.com/ https://gitlab.example.com/group/project`,
	Args: cobra.ExactArgs(1),
	Run:  runGitLab,
}

func runGitLab(cmd *cobra.Command, args []string) {
	start := time.Now()

	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, ".")

	targetURL := args[0]

	token := mustGetStringFlag(cmd, "token")
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}

	include, _ := cmd.Flags().GetStringSlice("include")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	excludeRepos, _ := cmd.Flags().GetStringSlice("exclude-repo")

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

	src := &sources.GitLab{
		Token:            token,
		URL:              targetURL,
		BaseURL:          mustGetStringFlag(cmd, "base-url"),
		Include:          include,
		Exclude:          exclude,
		ExcludeRepos:     excludeRepos,
		AllGroups:        mustGetBoolFlag(cmd, "all-groups"),
		IncludeSubgroups: mustGetBoolFlag(cmd, "include-subgroups"),
		ShouldSkip:       detector.SkipFunc(),
		Sema:             detector.Sema,
		MaxArchiveDepth:  detector.MaxArchiveDepth,
		Workers:          mustGetIntFlag(cmd, "git-workers"),
		LogOpts:          mustGetStringFlag(cmd, "log-opts"),
		DateRangeOpts: sources.DateRangeOptions{
			Since: since,
			Until: until,
		},
	}

	if err := src.Validate(); err != nil {
		logging.Fatal().Err(err).Msg("invalid GitLab configuration")
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
			if detector.LegacyPrint {
				result.Finding.PrintLegacy(noColor, redact)
			} else {
				result.Finding.Print(noColor, redact)
			}
		}
	}

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) during GitLab scan", n),
			errs: scanErrs,
		}
	}
	findingSummaryAndExit(detector, findings, exitCode, start, scanErr)
}
