package cmd

import (
	"path/filepath"
	"strings"
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
	sourcesList = removeNestedPaths(sourcesList)

	initDiagnostics()

	// start timer
	start := time.Now()
	followSymlinks := mustGetBoolFlag(cmd, "follow-symlinks")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")
	maxTargetMegaBytes := mustGetIntFlag(cmd, "max-target-megabytes")
	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	verbose := mustGetBoolFlag(cmd, "verbose")
	exitCode := mustGetIntFlag(cmd, "exit-code")

	var (
		allFindings  []report.Finding
		lastDetector *detect.Detector
		scanErr      error
	)

	totalBytes := uint64(0)

	for _, source := range sourcesList {
		initConfig(source)
		cfg := Config(cmd)
		detector := Detector(cmd, cfg, source)
		detector.SkipFindingAppend = true
		lastDetector = detector

		s := &sources.Files{
			ShouldSkip:      detector.SkipFunc(),
			FollowSymlinks:  followSymlinks,
			MaxFileSize:     maxTargetMegaBytes * 1_000_000,
			Path:            source,
			Sema:            detector.Sema,
			MaxArchiveDepth: maxArchiveDepth,
		}

		var findings []report.Finding
		for result := range detector.Run(cmd.Context(), s) {
			if result.Err != nil {
				logging.Error().Err(result.Err).Msg("error scanning source")
				continue
			}

			findings = append(findings, result.Finding)
			if verbose {
				result.Finding.Print(noColor, uint(redact))
			}
		}

		allFindings = append(allFindings, findings...)
		totalBytes += detector.TotalBytes.Load()
	}

	lastDetector.TotalBytes.Swap(totalBytes)

	findingSummaryAndExit(lastDetector, allFindings, exitCode, start, scanErr)
}

// removeNestedPaths filters out paths that are children of other paths in the
// list so that overlapping sources (e.g. "root" and "root/sub") don't produce
// duplicate findings.
func removeNestedPaths(paths []string) []string {
	abs := make([]string, len(paths))
	for i, p := range paths {
		a, err := filepath.Abs(p)
		if err != nil {
			abs[i] = p
			continue
		}
		abs[i] = a
	}

	var kept []string
	for i, candidate := range abs {
		nested := false
		for j, parent := range abs {
			if i == j {
				continue
			}
			if strings.HasPrefix(candidate, parent+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			kept = append(kept, paths[i])
		}
	}
	return kept
}
