package cmd

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/detect"
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
	sourcesList := args
	if len(sourcesList) == 0 {
		sourcesList = []string{"."}
	}

	initDiagnostics()

	// start timer
	start := time.Now()

	exitCode, err := cmd.Flags().GetInt("exit-code")
	if err != nil {
		logging.Fatal().Err(err).Msg("could not get exit code")
	}

	followSymlinks, err := cmd.Flags().GetBool("follow-symlinks")
	if err != nil {
		logging.Fatal().Err(err).Send()
	}

	var (
		allFindings  []report.Finding
		lastDetector *detect.Detector
		scanErr      error
	)
	for _, source := range sourcesList {
		initConfig(source)
		cfg := Config(cmd)
		detector := Detector(cmd, cfg, source)
		detector.FollowSymlinks = followSymlinks
		lastDetector = detector

		findings, detectErr := detector.DetectSource(
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
		if detectErr != nil {
			logging.Error().Err(detectErr).Str("source", source).Msg("failed scan")
			scanErr = detectErr
		}
		allFindings = append(allFindings, findings...)
	}

	findingSummaryAndExit(lastDetector, allFindings, exitCode, start, scanErr)
}
