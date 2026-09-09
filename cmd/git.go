package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// multipleErrors wraps multiple scan errors into a single error that supports
// errors.Unwrap so callers can inspect individual errors.
type multipleErrors struct {
	msg  string
	errs []error
}

func (e *multipleErrors) Error() string   { return e.msg }
func (e *multipleErrors) Unwrap() []error { return e.errs }

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().Bool("pre-receive", false, "run as a git pre-receive hook, scanning pushed commits read from stdin")
	gitCmd.Flags().String("pre-receive-error-message", "",
		"error message printed to stderr when the pre-receive hook finds leaks; "+
			"$VAR and ${VAR} are expanded from the environment")
	gitCmd.Flags().String("log-opts", "", "git log options")
	gitCmd.Flags().Int("git-workers", 0, "alias for --source-workers when scanning Git")
}

var gitCmd = &cobra.Command{
	Use:   "git [flags] [repo]",
	Short: "scan git repositories for secrets",
	Args:  cobra.MaximumNArgs(1),
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()

	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}

	// setup config (aka, the thing that defines rules)
	initConfig(source)
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, source)

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	logOpts := mustGetStringFlag(cmd, "log-opts")
	staged := mustGetBoolFlag(cmd, "staged")
	preCommit := mustGetBoolFlag(cmd, "pre-commit")
	preReceive := mustGetBoolFlag(cmd, "pre-receive")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")
	gitWorkers := mustGetIntFlag(cmd, "git-workers")
	sourceWorkers := mustGetIntFlag(cmd, "source-workers")
	workers, workerErr := resolveGitWorkers(sourceWorkers, gitWorkers)
	if workerErr != nil {
		logging.Fatal().Err(workerErr).Send()
	}
	findings := newFindingCollector(mustGetStringFlag(cmd, "report-path") != "")

	if preReceive && (preCommit || staged) {
		logging.Fatal().Msg("--pre-receive cannot be combined with --pre-commit or --staged")
	}
	if preReceive && logOpts != "" {
		logging.Fatal().Msg("--log-opts cannot be combined with --pre-receive")
	}

	var (
		err error
		src sources.Source
	)

	if preReceive {
		updates, parseErr := sources.ParsePreReceiveInput(cmd.InOrStdin())
		if parseErr != nil {
			logging.Fatal().Err(parseErr).Msg("could not read pre-receive input")
		}
		logArgs := sources.PreReceiveLogArgs(updates)
		if len(logArgs) == 0 {
			// Nothing to scan (e.g. only ref deletions). Report cleanly.
			logging.Info().Msg("pre-receive: no new commits to scan")
			findingSummaryAndExit(cmd, detector, findings, exitCode, start, nil)
			return
		}
		// Remote info + links are irrelevant for server-side hook scans.
		src = &sources.Git{
			RepoPath:        source,
			ShouldSkip:      detector.SkipFunc(),
			Platform:        scm.NoPlatform,
			MaxArchiveDepth: maxArchiveDepth,
			LogOpts:         strings.Join(logArgs, " "),
			Workers:         workers,
		}
	} else if preCommit || staged {
		gitCmd, cmdErr := sources.NewGitDiffCmdContext(cmd.Context(), source, staged)
		if cmdErr != nil {
			logging.Fatal().Err(cmdErr).Msg("could not create Git diff cmd")
		}
		// Remote info + links are irrelevant for staged changes.
		src = &sources.Git{
			Cmd:             gitCmd,
			ShouldSkip:      detector.SkipFunc(),
			Platform:        scm.NoPlatform,
			MaxArchiveDepth: maxArchiveDepth,
			Workers:         workers,
		}
	} else {
		scmPlatform, platformErr := scm.PlatformFromString(mustGetStringFlag(cmd, "platform"))
		if platformErr != nil {
			logging.Fatal().Err(platformErr).Send()
		}
		resolvedPlatform, remoteURL := sources.ResolveRemote(cmd.Context(), scmPlatform, source)

		src = &sources.Git{
			RepoPath:        source,
			ShouldSkip:      detector.SkipFunc(),
			Platform:        resolvedPlatform,
			RemoteURL:       remoteURL,
			MaxArchiveDepth: maxArchiveDepth,
			LogOpts:         logOpts,
			Workers:         workers,
		}
	}

	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			// don't exit on error, just log it
			logging.Error().Err(result.Err).Msg("failed to scan Git repository")
			continue
		}

		collectFinding(cmd, findings, result.Finding)
	}

	if n := len(scanErrs); n > 0 {
		err = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) encountered during scan", n),
			errs: scanErrs,
		}
	}

	// When running as a pre-receive hook, print the custom error message
	// (with environment variables expanded) so the pushing client sees it.
	if preReceive && findings.Count() != 0 {
		if msg := mustGetStringFlag(cmd, "pre-receive-error-message"); msg != "" {
			fmt.Fprintln(os.Stderr, os.ExpandEnv(msg))
		}
	}

	findingSummaryAndExit(cmd, detector, findings, exitCode, start, err)
}

func resolveGitWorkers(sourceWorkers, gitWorkers int) (int, error) {
	if sourceWorkers < 0 {
		return 0, fmt.Errorf("--source-workers must be non-negative")
	}
	if gitWorkers < 0 {
		return 0, fmt.Errorf("--git-workers must be non-negative")
	}
	if sourceWorkers > 0 && gitWorkers > 0 && sourceWorkers != gitWorkers {
		return 0, fmt.Errorf("--source-workers and --git-workers must match when both are set")
	}
	if sourceWorkers > 0 {
		return sourceWorkers, nil
	}
	return gitWorkers, nil
}
