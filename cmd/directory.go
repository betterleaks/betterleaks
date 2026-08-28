package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(directoryCmd)
	scanFlags(directoryCmd)
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

	initDiagnostics(cmd)

	// start timer
	start := time.Now()
	followSymlinks := mustGetBoolFlag(cmd, "follow-symlinks")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")
	maxTargetMegaBytes := mustGetIntFlag(cmd, "max-target-megabytes")
	exitCode := mustGetIntFlag(cmd, "exit-code")
	findings := mustNewFindingCollector(cmd)

	var (
		lastDetector *detect.Detector
		scanErrs     []error
	)

	totalBytes := uint64(0)

	for _, source := range sourcesList {
		initConfig(cmd, source)
		cfg := Config(cmd)
		detector := Detector(cmd, cfg, source)
		lastDetector = detector

		s := &sources.Files{
			ShouldSkip:      findings.FileSkipFunc(detector.SkipFunc()),
			FollowSymlinks:  followSymlinks,
			MaxFileSize:     maxTargetMegaBytes * 1_000_000,
			Path:            source,
			MaxArchiveDepth: maxArchiveDepth,
			Workers:         mustGetIntFlag(cmd, "source-workers"),
		}

		for result := range detector.Run(cmd.Context(), s) {
			if result.Err != nil {
				scanErrs = append(scanErrs, result.Err)
				logging.Error().Err(result.Err).Msg("error scanning source")
				continue
			}

			collectFinding(findings, result.Finding)
		}

		totalBytes += detector.TotalBytes.Load()
	}

	lastDetector.TotalBytes.Swap(totalBytes)

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) encountered during scan", n),
			errs: scanErrs,
		}
	}

	findingSummaryAndExit(cmd, lastDetector, findings, exitCode, start, scanErr)
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
