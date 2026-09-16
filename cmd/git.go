package cmd

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
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
	Token     string   `group:"source" help:"Token for an HTTP(S) clone (or the known host's GITHUB_TOKEN, GITLAB_TOKEN, HUGGINGFACE_TOKEN/HF_TOKEN)."`
	Platform  string   `group:"source" help:"Target platform used to generate links: github or gitlab."`
	Staged    bool     `group:"source" help:"Scan staged commits (for pre-commit)."`
	PreCommit bool     `group:"source" name:"pre-commit" help:"Scan using git diff."`
	LogOpts   string   `group:"source" name:"log-opts" help:"Git log options."`
	Include   []string `group:"source" help:"Additional Git resources to scan: commit-messages, tag-messages, reflogs."`
	Repo      string   `arg:"" optional:"" help:"Local repository or HTTP(S) repository URL to scan."`
}

func (cmd GitCmd) Validate() error {
	if err := cmd.ScanFlags.Validate(); err != nil {
		return err
	}
	if remoteGitURL(cmd.Repo) && (cmd.Staged || cmd.PreCommit) {
		return errors.New("--staged and --pre-commit require a local Git repository")
	}
	if len(cmd.Include) > 0 && (cmd.Staged || cmd.PreCommit) {
		return errors.New("--include requires a Git history scan; it cannot be combined with --staged or --pre-commit")
	}
	return (&sources.Git{Include: cmd.Include}).Validate()
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
	configSource, ignoreSource := source, source
	remote := remoteGitURL(source)
	if remote {
		configSource, ignoreSource = ".", ""
	}
	initConfig(runtime, globals, &options.ScanFlags, configSource)
	initDiagnostics(runtime, &options.ScanFlags)

	cfg := Config(runtime)

	// create runner
	workers := resolveWorkerPlan(options.Jobs, gitWorkerProfile)
	runner := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, ignoreSource, scan.WithWorkers(workers.Scanner))

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor)

	var (
		err error
		src sources.Source
	)

	if options.PreCommit || options.Staged {
		gitCmd, cmdErr := sources.NewGitDiffCmdContext(runtime.Context, source, options.Staged, sources.WithGitCmdLogger(runtime.Logger()))
		if cmdErr != nil {
			runtime.fatal("could not create Git diff cmd", "error", cmdErr)
		}
		// Remote info + links are irrelevant for staged changes.
		src = &sources.Git{
			Logger:          runtime.Logger(),
			Cmd:             gitCmd,
			ShouldSkip:      runner.SkipFunc(),
			Platform:        scm.NoPlatform,
			MaxArchiveDepth: options.MaxArchiveDepth,
			Workers:         workers.Source,
		}
	} else {
		scmPlatform, platformErr := scm.PlatformFromString(options.Platform)
		if platformErr != nil {
			runtime.fatal("invalid platform", "error", platformErr)
		}
		resolvedPlatform, remoteURL := scmPlatform, ""
		if !remote {
			resolvedPlatform, remoteURL = sources.ResolveRemote(runtime.Context, scmPlatform, source)
		}

		gitSource := &sources.Git{
			Logger:          runtime.Logger(),
			RepoPath:        source,
			ShouldSkip:      runner.SkipFunc(),
			Platform:        resolvedPlatform,
			RemoteURL:       remoteURL,
			MaxArchiveDepth: options.MaxArchiveDepth,
			LogOpts:         options.LogOpts,
			Include:         options.Include,
			Workers:         workers.Source,
		}
		if remote {
			gitSource.RepoPath = ""
			gitSource.URL = source
			gitSource.Token = options.Token
			if gitSource.Token == "" {
				gitSource.Token = remoteGitToken(source)
			}
		}
		src = gitSource
	}

	summary, err := runner.Scan(runtime.Context, src, findings.Add)
	if err != nil {
		runtime.Logger().Error("failed to scan Git repository", "error", err)
	}

	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, err)
}

// An existing path wins even when its spelling resembles a URL.
func remoteGitURL(target string) bool {
	if _, err := os.Stat(target); err == nil {
		return false
	}
	u, err := url.Parse(target)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func remoteGitToken(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return ""
	}
	switch strings.ToLower(u.Host) {
	case "github.com":
		return os.Getenv("GITHUB_TOKEN")
	case "gitlab.com":
		return os.Getenv("GITLAB_TOKEN")
	case "huggingface.co":
		if token := os.Getenv("HUGGINGFACE_TOKEN"); token != "" {
			return token
		}
		return os.Getenv("HF_TOKEN")
	}
	return ""
}

// Match clone authentication, without forwarding environment tokens on redirects.
type gitAutoTransport struct {
	host  string
	token string
}

func (t gitAutoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && req.URL.Host == t.host {
		req = req.Clone(req.Context())
		req.SetBasicAuth("x-access-token", t.token)
	}
	return http.DefaultTransport.RoundTrip(req)
}
