// The `detect` and `protect` command is now deprecated. Here are some equivalent commands
// to help guide you.

// OLD CMD: betterleaks detect --source={repo}
// NEW CMD: betterleaks git {repo}

// OLD CMD: betterleaks protect --source={repo}
// NEW CMD: betterleaks git --pre-commit {repo}

// OLD  CMD: betterleaks protect --staged --source={repo}
// NEW CMD: betterleaks git --pre-commit --staged {repo}

// OLD CMD: betterleaks detect --no-git --source={repo}
// NEW CMD: betterleaks directory {directory/file}

// OLD CMD: betterleaks detect --no-git --pipe
// NEW CMD: betterleaks stdin

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

func init() {
	rootCmd.AddCommand(detectCmd)
	detectCmd.Flags().Bool("no-git", false, "treat git repo as a regular directory and scan those files, --log-opts has no effect on the scan when --no-git is set")
	detectCmd.Flags().Bool("pipe", false, "scan input from stdin, ex: `cat some_file | betterleaks detect --pipe`")
	detectCmd.Flags().StringArray("set-attr", nil, "set source attribute for piped content, key=value (repeatable)")
	detectCmd.Flags().Bool("follow-symlinks", false, "scan files that are symlinks to other files")
	detectCmd.Flags().StringP("source", "s", ".", "path to source")
	detectCmd.Flags().String("log-opts", "", "git log options")
	detectCmd.Flags().String("platform", "", "the target platform used to generate links (github, gitlab)")
}

var detectCmd = &cobra.Command{
	Use:    "detect",
	Short:  "detect secrets in code",
	Run:    runDetect,
	Hidden: true,
}

func runDetect(cmd *cobra.Command, args []string) {
	// start timer
	start := time.Now()
	sourcePath := mustGetStringFlag(cmd, "source")

	// setup config (aka, the thing that defines rules)
	initConfig(sourcePath)
	initDiagnostics()
	cfg := Config(cmd)

	// create detector
	detector := Detector(cmd, cfg, sourcePath)

	// parse flags
	followSymlinks := mustGetBoolFlag(cmd, "follow-symlinks")
	maxArchiveDepth := mustGetIntFlag(cmd, "max-archive-depth")
	maxTargetMegaBytes := mustGetIntFlag(cmd, "max-target-megabytes")
	exitCode := mustGetIntFlag(cmd, "exit-code")
	noGit := mustGetBoolFlag(cmd, "no-git")
	fromPipe := mustGetBoolFlag(cmd, "pipe")
	// determine what type of scan:
	// - git: scan the history of the repo
	// - no-git: scan files by treating the repo as a plain directory
	var (
		err error
		src sources.Source
	)
	if noGit {
		src = &sources.Files{
			ShouldSkip:      detector.SkipFunc(),
			FollowSymlinks:  followSymlinks,
			MaxFileSize:     maxTargetMegaBytes * 1_000_000,
			Path:            sourcePath,
			MaxArchiveDepth: maxArchiveDepth,
			Workers:         mustGetIntFlag(cmd, "source-workers"),
		}
	} else if fromPipe {
		attrs, attrErr := parseSetAttrFlag(cmd)
		if attrErr != nil {
			logging.Fatal().Err(attrErr).Msg("invalid --set-attr value")
		}

		src = newStdinSource(os.Stdin, attrs, detector.SkipFunc(), maxArchiveDepth)
	} else {
		logOpts := mustGetStringFlag(cmd, "log-opts")
		scmPlatform, platformErr := scm.PlatformFromString(mustGetStringFlag(cmd, "platform"))
		if platformErr != nil {
			logging.Fatal().Err(platformErr).Send()
		}
		resolvedPlatform, remoteURL := sources.ResolveRemote(cmd.Context(), scmPlatform, sourcePath)

		src = &sources.Git{
			RepoPath:        sourcePath,
			ShouldSkip:      detector.SkipFunc(),
			Platform:        resolvedPlatform,
			RemoteURL:       remoteURL,
			MaxArchiveDepth: maxArchiveDepth,
			LogOpts:         logOpts,
			Workers:         mustGetIntFlag(cmd, "source-workers"),
		}
	}

	findings := newFindingCollector(mustGetStringFlag(cmd, "report-path") != "")
	var scanErrs []error
	for result := range detector.Run(cmd.Context(), src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			logging.Error().Err(result.Err).Msg("scan error")
			continue
		}
		collectFinding(cmd, findings, result.Finding)
	}
	if n := len(scanErrs); n > 0 {
		err = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) encountered during scan", n),
			errs: scanErrs,
		}
	}

	findingSummaryAndExit(cmd, detector, findings, exitCode, start, err)
}
