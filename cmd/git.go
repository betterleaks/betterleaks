package cmd

import (
	"context"
	"time"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/scan"
	"github.com/betterleaks/betterleaks/sources/git"
	"github.com/betterleaks/betterleaks/sources/scm"
	"github.com/fatih/semgroup"
	"github.com/spf13/cobra"
)

// multiSource composes multiple betterleaks.Source implementations into one,
// running each sequentially.
type multiSource []betterleaks.Source

func (m multiSource) Fragments(ctx context.Context, yield betterleaks.FragmentsFunc) error {
	for _, s := range m {
		if err := s.Fragments(ctx, yield); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(gitCmd)
	gitCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
	gitCmd.Flags().Bool("staged", false, "scan staged commits (good for pre-commit)")
	gitCmd.Flags().Bool("pre-commit", false, "scan using git diff")
	gitCmd.Flags().String("log-opts", "", "git log options")
	gitCmd.Flags().Int("git-workers", 0, "number of parallel git log workers (0 = single process, default)")
	gitCmd.Flags().Bool("include-dangling", false, "scan dangling commits not reachable from any ref or reflog")
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
	maxDecodeDepth := mustGetIntFlag(cmd, "max-decode-depth")
	verbose := mustGetBoolFlag(cmd, "verbose")
	includeDangling := mustGetBoolFlag(cmd, "include-dangling")

	var (
		err         error
		src         betterleaks.Source
		scmPlatform scm.Platform
	)

	sema := semgroup.NewGroup(cmd.Context(), 10)

	if preCommit || staged {
		scmPlatform = scm.NoPlatform
	} else {
		if scmPlatform, err = scm.PlatformFromString(mustGetStringFlag(cmd, "platform")); err != nil {
			logging.Fatal().Err(err).Send()
		}
	}

	remote := git.NewRemoteInfoContext(cmd.Context(), scmPlatform, source)

	gitWorkers := mustGetIntFlag(cmd, "git-workers")

	if preCommit || staged {
		var gitDiffCmd *git.GitCmd
		if gitDiffCmd, err = git.NewGitDiffCmdContext(cmd.Context(), source, staged); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git diff cmd")
		}
		src = &git.Git{
			Cmd:             gitDiffCmd,
			Config:          &cfg,
			Remote:          remote,
			Sema:            sema,
			MaxArchiveDepth: maxArchiveDepth,
		}
	} else if gitWorkers > 0 {
		src = &git.ParallelGit{
			RepoPath:        source,
			Config:          &cfg,
			Remote:          remote,
			Sema:            sema,
			MaxArchiveDepth: maxArchiveDepth,
			LogOpts:         logOpts,
			Workers:         gitWorkers,
			IncludeDangling: includeDangling,
		}
	} else {
		var gitLogCmd *git.GitCmd
		if gitLogCmd, err = git.NewGitLogCmdContext(cmd.Context(), source, logOpts); err != nil {
			logging.Fatal().Err(err).Msg("could not create Git log cmd")
		}
		mainSrc := &git.Git{
			Cmd:             gitLogCmd,
			Config:          &cfg,
			Remote:          remote,
			Sema:            sema,
			MaxArchiveDepth: maxArchiveDepth,
		}

		if includeDangling {
			logging.Info().Msg("scanning for dangling commits via git fsck")
			dangling, danglingErr := git.ListDanglingCommits(cmd.Context(), source)
			if danglingErr != nil {
				logging.Warn().Err(danglingErr).Msg("could not list dangling commits")
			}
			if len(dangling) > 0 {
				logging.Info().Int("count", len(dangling)).Msg("found dangling commits")
				danglingCmd, danglingErr := git.NewGitLogCommitsCmd(cmd.Context(), source, dangling)
				if danglingErr != nil {
					logging.Fatal().Err(danglingErr).Msg("could not create dangling commits cmd")
				}
				danglingSrc := &git.Git{
					Cmd:             danglingCmd,
					Config:          &cfg,
					Remote:          remote,
					Sema:            sema,
					MaxArchiveDepth: maxArchiveDepth,
				}
				src = multiSource{mainSrc, danglingSrc}
			} else {
				logging.Info().Msg("no dangling commits found")
				src = mainSrc
			}
		} else {
			src = mainSrc
		}
	}

	scanner := scan.NewScanner(cmd.Context(), &cfg, maxDecodeDepth, false, 10)

	// Load ignore files
	ignorePath := mustGetStringFlag(cmd, "gitleaks-ignore-path")
	if altPath := mustGetStringFlag(cmd, "betterleaks-ignore-path"); altPath != "" {
		ignorePath = altPath
	}
	scanner.SetIgnore(scan.LoadIgnoreFiles(ignorePath, source))

	p := scan.NewPipeline(cfg, src, *scanner)

	var findings []betterleaks.Finding
	noColor := mustGetBoolFlag(cmd, "no-color")
	legacy := mustGetBoolFlag(cmd, "legacy")
	start := time.Now()

	err = p.Run(cmd.Context(), func(finding betterleaks.Finding, err error) error {
		if err != nil {
			return err
		}

		if link := scan.CreateScmLink(remote, finding); link != "" {
			finding.Metadata[betterleaks.MetaLink] = link
		}

		if verbose {
			// Legacy: use gitleaks-compatible print format.
			if legacy {
				scan.LegacyPrintFinding(finding, noColor)
			} else {
				scan.PrintFinding(finding, noColor)
			}
		}

		findings = append(findings, finding)
		return nil
	})

	findingSummary(cmd, cfg, findings, start, err, p.TotalBytes())
}
