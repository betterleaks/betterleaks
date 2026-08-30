package cmd

import (
	"fmt"
	"time"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// multipleErrors wraps multiple scan errors into a single error that supports
// errors.Unwrap so callers can inspect individual errors.
type multipleErrors struct {
	msg  string
	errs []error
}

func (e *multipleErrors) Error() string   { return e.msg }
func (e *multipleErrors) Unwrap() []error { return e.errs }

type GitCmd struct {
	ScanFlags `embed:""`
	Platform  string `help:"Target platform used to generate links: github or gitlab."`
	Staged    bool   `help:"Scan staged commits (for pre-commit)."`
	PreCommit bool   `name:"pre-commit" help:"Scan using git diff."`
	LogOpts   string `name:"log-opts" help:"Git log options."`
	Repo      string `arg:"" optional:"" help:"Repository to scan."`
}

func (cmd *GitCmd) Run(cli *CLI, runtime *commandRuntime) error {
	runGit(runtime, &cli.GlobalFlags, cmd)
	return nil
}

func runGit(runtime *commandRuntime, globals *GlobalFlags, options *GitCmd) {
	// start timer
	start := time.Now()

	// grab source
	source := "."
	if options.Repo != "" {
		source = options.Repo
		if source == "" {
			source = "."
		}
	}

	// setup config (aka, the thing that defines rules)
	initConfig(runtime, globals, &options.ScanFlags, source)
	initDiagnostics(&options.ScanFlags)

	cfg := Config()

	// create detector
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, source)
	jobs := resolveJobPlan(options.Jobs, gitJobProfile)
	detector.Jobs = jobs.Detector

	findings := mustNewFindingCollector(&options.ScanFlags, globals.NoColor, runtime.stdout)

	var (
		err error
		src sources.Source
	)

	if options.PreCommit || options.Staged {
		gitCmd, cmdErr := sources.NewGitDiffCmdContext(runtime.Context, source, options.Staged)
		if cmdErr != nil {
			logging.Fatal().Err(cmdErr).Msg("could not create Git diff cmd")
		}
		// Remote info + links are irrelevant for staged changes.
		src = &sources.Git{
			Cmd:             gitCmd,
			ShouldSkip:      detector.SkipFunc(),
			Platform:        scm.NoPlatform,
			MaxArchiveDepth: options.MaxArchiveDepth,
			Jobs:            jobs.Source,
		}
	} else {
		scmPlatform, platformErr := scm.PlatformFromString(options.Platform)
		if platformErr != nil {
			logging.Fatal().Err(platformErr).Send()
		}
		resolvedPlatform, remoteURL := sources.ResolveRemote(runtime.Context, scmPlatform, source)

		src = &sources.Git{
			RepoPath:        source,
			ShouldSkip:      detector.SkipFunc(),
			Platform:        resolvedPlatform,
			RemoteURL:       remoteURL,
			MaxArchiveDepth: options.MaxArchiveDepth,
			LogOpts:         options.LogOpts,
			Jobs:            jobs.Source,
		}
	}

	var scanErrs []error
	for result := range detector.Run(runtime.Context, src) {
		if result.Err != nil {
			scanErrs = append(scanErrs, result.Err)
			// don't exit on error, just log it
			logging.Error().Err(result.Err).Msg("failed to scan Git repository")
			continue
		}

		collectFinding(findings, result.Finding)
	}

	if n := len(scanErrs); n > 0 {
		err = &multipleErrors{
			msg:  fmt.Sprintf("%d error(s) encountered during scan", n),
			errs: scanErrs,
		}
	}

	findingSummaryAndExit(runtime, detector, findings, options.ExitCode, start, err)
}
