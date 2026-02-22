package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

func init() {
	protectCmd.Flags().Bool("staged", false, "detect secrets in a --staged state")
	protectCmd.Flags().String("log-opts", "", "git log options")
	protectCmd.Flags().StringP("source", "s", ".", "path to source")
	rootCmd.AddCommand(protectCmd)
}

var protectCmd = &cobra.Command{
	Use:    "protect",
	Short:  "protect secrets in code",
	Run:    runProtect,
	Hidden: true,
}

func runProtect(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()
	source := mustGetStringFlag(cmd, "source")

	// setup config (aka, the thing that defines rules)
	initConfig(source)
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, source)

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	staged := mustGetBoolFlag(cmd, "staged")

	// start git scan
	var (
		findings []report.Finding
		err      error
		gitCmd   *sources.GitCmd
	)

	if gitCmd, err = sources.NewGitDiffCmdContext(cmd.Context(), source, staged); err != nil {
		logging.Fatal().Err(err).Msg("could not create Git diff cmd")
	}
	src := &sources.Git{
		Cmd:             gitCmd,
		Config:          &detector.Config,
		Remote:          &sources.RemoteInfo{Platform: scm.NoPlatform},
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
	}

	if findings, err = detector.DetectSource(cmd.Context(), src); err != nil {
		// don't exit on error, just log it
		logging.Error().Err(err).Msg("failed to scan Git repository")
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
