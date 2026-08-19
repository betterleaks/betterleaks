package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

func init() {
	rootCmd.AddCommand(diffCmd)
	diffCmd.Flags().Int("strip-components", 0,
		"strip leading path components from reported paths, as `patch -p` does "+
			"(use 1 for a bare unified diff with no \"diff --git\" headers)")
}

var diffCmd = &cobra.Command{
	Use:   "diff [flags] [patch]",
	Short: "scan a pre-computed unified diff for secrets",
	Long: `Scan a unified diff that was produced elsewhere, such as the output of
"git log -p" or "git diff".

Use this when the content to scan is only available as a diff: the repository
the diff came from may be unreachable, may not exist yet, or may not be git at
all, so long as the diff is git-formatted.

The patch is read from the given file, or from stdin when the path is "-" or
omitted. Only added lines are scanned, and findings are reported against the
path and line numbers of the file the patch produces, so they line up with a
scan of the resulting repository. Commit, author and date are taken from the
patch headers when it has them, as "git log -p" output does.

A patch that cannot be read to its end fails the scan rather than being
reported as a scan that found nothing.`,
	Args: cobra.MaximumNArgs(1),
	Run:  runDiff,
}

func runDiff(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()

	patchPath := "-"
	if len(args) == 1 && args[0] != "" {
		patchPath = args[0]
	}

	// setup config (aka, the thing that defines rules)
	initConfig(".")
	initDiagnostics()

	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, "")

	// parse flags
	exitCode := mustGetIntFlag(cmd, "exit-code")
	stripComponents := mustGetIntFlag(cmd, "strip-components")
	noColor := mustGetBoolFlag(cmd, "no-color")
	redact := mustGetUIntFlag(cmd, "redact")
	verbose := mustGetBoolFlag(cmd, "verbose")

	if stripComponents < 0 {
		logging.Fatal().Int("strip-components", stripComponents).
			Msg("--strip-components cannot be negative")
	}

	var patch io.Reader
	if patchPath == "-" {
		patch = os.Stdin
	} else {
		file, err := os.Open(patchPath)
		if err != nil {
			logging.Fatal().Err(err).Str("path", patchPath).Msg("could not open patch")
		}
		defer func() {
			if err := file.Close(); err != nil {
				logging.Debug().Err(err).Msg("could not close patch")
			}
		}()
		patch = file
	}

	gitCmd, err := sources.NewGitPatchCmd(patch, sources.GitPatchOptions{
		StripComponents: stripComponents,
	})
	if err != nil {
		logging.Fatal().Err(err).Msg("could not parse patch")
	}

	src := &sources.Git{
		Cmd:             gitCmd,
		ShouldSkip:      detector.SkipFunc(),
		Platform:        scm.NoPlatform,
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
	}

	var findings []report.Finding
	detector.SkipFindingAppend = true
	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			// don't exit on error, just log it
			logging.Error().Err(result.Err).Msg("failed to scan patch")
			continue
		}

		findings = append(findings, result.Finding)
		if verbose {
			if detector.LegacyPrint {
				result.Finding.PrintLegacy(noColor, redact)
			} else {
				result.Finding.Print(noColor, redact)
			}
		}
	}

	if n := len(scanErrs); n > 0 {
		err = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) encountered during scan", n),
			errs: scanErrs,
		}
	}

	findingSummaryAndExit(detector, findings, exitCode, start, err)
}
