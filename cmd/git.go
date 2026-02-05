package cmd

import (
	"fmt"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/scan"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
	"github.com/fatih/semgroup"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
}

var gitCmd = &cobra.Command{
	Use:   "git [flags] [repo]",
	Short: "scan git repositories for secrets",
	Args:  cobra.MaximumNArgs(1),
	Run:   runGit,
}

func runGit(cmd *cobra.Command, args []string) {
	// grab source
	source := "."
	if len(args) == 1 {
		source = args[0]
		if source == "" {
			source = "."
		}
	}

	initConfig(source)
	initDiagnostics()

	cfg := Config(cmd)

	// parse flags
	logOpts := mustGetStringFlag(cmd, "log-opts")
	staged := mustGetBoolFlag(cmd, "staged")
	preCommit := mustGetBoolFlag(cmd, "pre-commit")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")

	var (
		err         error
		gitCmd      *sources.GitCmd
		scmPlatform scm.Platform
	)

	if preCommit || staged {
		if gitCmd, err = sources.NewGitDiffCmdContext(cmd.Context(), source, staged); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git diff cmd")
		}
		// Remote info + links are irrelevant for staged changes.
		scmPlatform = scm.NoPlatform
	} else {
		if gitCmd, err = sources.NewGitLogCmdContext(cmd.Context(), source, logOpts); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git log cmd")
		}
		if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}
	}

	src := &sources.Git{
		Cmd:             gitCmd,
		Config:          &cfg,
		Remote:          sources.NewRemoteInfoContext(cmd.Context(), scmPlatform, source),
		Sema:            semgroup.NewGroup(cmd.Context(), 10),
		MaxArchiveDepth: maxArchiveDepth,
	}

	scanner := scan.NewScanner(cmd.Context(), &cfg, 0, false, 10)

	p := scan.NewPipeline(cfg, src, *scanner)

	var count int

	err = p.Run(cmd.Context(), func(finding betterleaks.Finding, err error) error {
		if err != nil {
			return err
		}
		scan.PrintFinding(finding, false)
		count++
		return nil
	})
	if err != nil {
		logging.Error().Err(err).Msg("failed to scan Git repository")
		return
	}

	fmt.Println(count)
}
