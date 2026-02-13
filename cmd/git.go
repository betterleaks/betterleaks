package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/cmd/scm"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
	gitCmd.Flags().Int("git-workers", 0, "number of parallel git log workers (0 = single process)")
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
	gitWorkers := mustGetIntFlag(cmd, "git-workers")

	var (
		findings    []report.Finding
		err         error
		src         sources.Source
		scmPlatform scm.Platform
	)

	if preCommit || staged {
		gitCmd, cmdErr := sources.NewGitDiffCmdContext(cmd.Context(), source, staged)
		if cmdErr != nil {
			logging.Fatal().Err(cmdErr).Msg("could not create Git diff cmd")
		}
		// Remote info + links are irrelevant for staged changes.
		scmPlatform = scm.NoPlatform
		src = &sources.Git{
			Cmd:             gitCmd,
			Config:          &detector.Config,
			Remote:          sources.NewRemoteInfoContext(cmd.Context(), scmPlatform, source),
			Sema:            detector.Sema,
			MaxArchiveDepth: detector.MaxArchiveDepth,
		}
	} else {
		if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}

		if gitWorkers > 0 {
			src = &sources.ParallelGit{
				RepoPath:        source,
				Config:          &detector.Config,
				Remote:          sources.NewRemoteInfoContext(cmd.Context(), scmPlatform, source),
				Sema:            detector.Sema,
				MaxArchiveDepth: detector.MaxArchiveDepth,
				LogOpts:         logOpts,
				Workers:         gitWorkers,
			}
		} else {
			gitCmd, cmdErr := sources.NewGitLogCmdContext(cmd.Context(), source, logOpts)
			if cmdErr != nil {
				logging.Fatal().Err(cmdErr).Msg("could not create Git log cmd")
			}
			src = &sources.Git{
				Cmd:             gitCmd,
				Config:          &detector.Config,
				Remote:          sources.NewRemoteInfoContext(cmd.Context(), scmPlatform, source),
				Sema:            detector.Sema,
				MaxArchiveDepth: detector.MaxArchiveDepth,
			}
		}
	}

	findings, err = detector.DetectSource(cmd.Context(), src)

	if err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed to scan Git repository")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
