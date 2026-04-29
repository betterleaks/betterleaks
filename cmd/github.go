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
	githubCmd.Flags().Int("git-workers", 0, "parallel git workers per repo (0 = single process)")
	githubCmd.Flags().String("log-opts", "", "git log options passed to each repo scan")
	githubCmd.Flags().String("github-url", "", "GitHub Enterprise base URL")
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

	orgs, _ := cmd.Flags().GetStringSlice("org")
	users, _ := cmd.Flags().GetStringSlice("user")
	repos, _ := cmd.Flags().GetStringSlice("repo")

	if len(orgs) == 0 && len(users) == 0 && len(repos) == 0 {
		logging.Fatal().Msg("at least one --org, --user, or --repo is required")
	}

	excludeRepos, _ := cmd.Flags().GetStringSlice("exclude-repo")

	src := &sources.GitHub{
		Token:           token,
		Repos:           repos,
		Orgs:            orgs,
		Users:           users,
		ExcludeRepos:    excludeRepos,
		ExcludeForks:    mustGetBoolFlag(cmd, "exclude-forks"),
		ShouldSkip:      detector.SkipFunc(),
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
		Workers:         mustGetIntFlag(cmd, "git-workers"),
		LogOpts:         mustGetStringFlag(cmd, "log-opts"),
		BaseURL:         mustGetStringFlag(cmd, "github-url"),
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
