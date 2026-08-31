package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

type DirectoryCmd struct {
	ScanFlags      `embed:""`
	FollowSymlinks bool     `name:"follow-symlinks" help:"Scan files that are symlinks to other files."`
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

	initDiagnostics(&options.ScanFlags)
	jobs := resolveJobPlan(options.Jobs, directoryJobProfile)

	// start timer
	start := time.Now()
	findings := mustNewFindingCollector(&options.ScanFlags, globals.NoColor, runtime.stdout)

	var (
		summary           detect.ScanSummary
		validationEnabled bool
		scanErrs          []error
	)

	for _, source := range sourcesList {
		initConfig(runtime, globals, &options.ScanFlags, source)
		cfg := Config()
		detector := Detector(runtime, globals, &options.ScanFlags, cfg, source, detect.WithJobs(jobs.Detector))
		validationEnabled = validationEnabled || detector.ValidationEnabled()

		s := &sources.Files{
			ShouldSkip:      findings.FileSkipFunc(detector.SkipFunc()),
			FollowSymlinks:  options.FollowSymlinks,
			MaxFileSize:     options.MaxTargetMegabytes * 1_000_000,
			Path:            source,
			MaxArchiveDepth: options.MaxArchiveDepth,
			Jobs:            jobs.Source,
		}

		nextSummary, scanErr := detector.Scan(runtime.Context, s, findings.Add)
		addScanSummary(&summary, nextSummary)
		if scanErr != nil {
			scanErrs = append(scanErrs, scanErr)
			logging.Error().Err(scanErr).Msg("error scanning source")
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
