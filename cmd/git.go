package cmd

import (
	"time"

	"github.com/betterleaks/betterleaks/detect"
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
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config()

	// create detector
	jobs := resolveJobPlan(options.Jobs, gitJobProfile)
	detector := Detector(runtime, globals, &options.ScanFlags, cfg, source, detect.WithJobs(jobs.Detector))

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

	summary, err := detector.Scan(runtime.Context, src, findings.Add)
	if err != nil {
		logging.Error().Err(err).Msg("failed to scan Git repository")
	}

	findingSummaryAndExit(runtime, summary, detector.ValidationEnabled(), findings, options.ExitCode, start, err)
}
