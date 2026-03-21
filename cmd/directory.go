package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(directoryCmd)
	directoryCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
}

var directoryCmd = &cobra.Command{
	Use:     "dir [flags] [path...]",
	Aliases: []string{"file", "directory"},
	Short:   "scan directories or files for secrets",
	Run:     runDirectory,
}

func runDirectory(cmd *cobra.Command, args []string) {
	// grab sources
	sources_list := args
	if len(sources_list) == 0 {
		sources_list = []string{"."}
	}

	initConfig(sources_list[0])
	initDiagnostics()
	var err error

	// setup config (aka, the thing that defines rules)
	cfg := Config(cmd)

	// start timer
	start := time.Now()

	detector := Detector(cmd, cfg, sources_list[0])

	// set follow symlinks flag
	if detector.FollowSymlinks, err = cmd.Flags().GetBool("follow-symlinks"); err != nil {
		logging.Fatal().Err(err).Send()
	}

	// set exit code
	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		logging.Fatal().Err(err).Msg("could not get exit code")
	}

	var allFindings []report.Finding
	for _, source := range sources_list {
		findings, scanErr := detector.DetectSource(
			cmd.Context(),
			&sources.Files{
				Config:          &cfg,
				FollowSymlinks:  detector.FollowSymlinks,
				MaxFileSize:     detector.MaxTargetMegaBytes * 1_000_000,
				Path:            source,
				Sema:            detector.Sema,
				MaxArchiveDepth: detector.MaxArchiveDepth,
			},
		)
		if scanErr != nil {
			logging.Error().Err(scanErr).Str("source", source).Msg("failed scan")
			err = scanErr
		}
		allFindings = append(allFindings, findings...)
	}

	findingSummaryAndExit(detector, allFindings, exitCode, start, err)
}
