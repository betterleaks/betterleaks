package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/pipeline"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

type DirectoryCmd struct {
	ScanFlags      `embed:""`
	FollowSymlinks bool     `group:"scanning" name:"follow-symlinks" help:"Follow symlinks to files and directories."`
	Paths          []string `arg:"" optional:"" name:"path" help:"Directories or files to scan."`
}

func (cmd *DirectoryCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runDirectory(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runDirectory(runtime *commandRuntime, globals *GlobalFlags, options *DirectoryCmd) {
	sourcesList := options.Paths
	if len(sourcesList) == 0 {
		sourcesList = []string{"."}
	}
	sourcesList = removeNestedPaths(sourcesList)

	initDiagnostics(runtime, &options.ScanFlags)

	// start timer
	start := time.Now()
	cfg := initConfig(runtime, globals, &options.ScanFlags)
	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "filesystem", sourcesList...)

	var (
		summary           pipeline.ScanSummary
		validationEnabled bool
		scanErrs          []error
	)

	for _, source := range sourcesList {
		// Once output is open, setup failures must also reach report finalization.
		filters, err := loadScanFilters(runtime, cfg, options.IgnoreFile, source)
		if err != nil {
			scanErrs = append(scanErrs, err)
			runtime.Logger().Error("unable to prepare source", "path", source, "error", err)
			break
		}
		runner, err := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))
		if err != nil {
			scanErrs = append(scanErrs, err)
			runtime.Logger().Error("unable to prepare scan", "error", err)
			break
		}
		validationEnabled = validationEnabled || runner.ValidationEnabled()

		s := &sources.Files{
			Logger:          runtime.Logger(),
			ShouldSkip:      findings.FileSkipFunc(filters.shouldSkip),
			FollowSymlinks:  options.FollowSymlinks,
			MaxFileSize:     options.MaxTargetMegabytes * 1_000_000,
			Path:            source,
			MaxArchiveDepth: options.MaxArchiveDepth,
		}

		findings.startScan(runtime)
		nextSummary, scanErr := runner.Scan(runtime.Context, s, findings.Add)
		addScanSummary(&summary, nextSummary)
		if scanErr != nil {
			scanErrs = append(scanErrs, scanErr)
			runtime.Logger().Error("error scanning source", "error", scanErr)
		}
	}

	var scanErr error
	if n := len(scanErrs); n > 0 {
		scanErr = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) encountered during scan", n),
			errs: scanErrs,
		}
	}

	findingSummaryAndExit(runtime, summary, validationEnabled, findings, options.ExitCode, start, scanErr)
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
