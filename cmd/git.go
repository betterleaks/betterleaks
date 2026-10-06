package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/pipeline"
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
	ScanFlags       `embed:""`
	MaxArchiveDepth int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Allow scanning into nested archives up to this depth."`
	Token           string   `group:"source" help:"Token for an HTTP(S) clone (or the known host's GITHUB_TOKEN, GITLAB_TOKEN, HUGGINGFACE_TOKEN/HF_TOKEN)."`
	Platform        string   `group:"source" help:"Target platform used to generate links: github or gitlab."`
	Staged          bool     `group:"source" help:"Scan added lines in staged changes."`
	Unstaged        bool     `group:"source" help:"Scan added lines in unstaged changes to tracked files."`
	PreReceive      bool     `group:"source" name:"pre-receive" help:"Run as a Git pre-receive hook, scanning pushed commits read from stdin."`
	PreReceiveError string   `group:"source" name:"pre-receive-error-message" help:"Message printed to stderr when the pre-receive hook finds leaks; environment variables in $$VAR and $${VAR} form are expanded."`
	LogOpts         string   `group:"source" name:"log-opts" help:"Git log options (uses one history stream to preserve option semantics)."`
	Include         []string `group:"source" help:"Additional Git resources to scan: commit-messages, tag-messages, reflogs."`
	Repo            string   `arg:"" optional:"" help:"Local repository or HTTP(S) repository URL to scan."`
}

func (cmd GitCmd) Validate() error {
	if err := cmd.ScanFlags.Validate(); err != nil {
		return err
	}
	if cmd.Staged && cmd.Unstaged {
		return errors.New("--staged and --unstaged are mutually exclusive")
	}
	if cmd.PreReceive && (cmd.Staged || cmd.Unstaged) {
		return errors.New("--pre-receive cannot be combined with --staged or --unstaged")
	}
	if cmd.PreReceive && cmd.LogOpts != "" {
		return errors.New("--pre-receive cannot be combined with --log-opts")
	}
	if cmd.PreReceive && remoteGitURL(cmd.Repo) {
		return errors.New("--pre-receive requires a local Git repository")
	}
	if cmd.PreReceive && len(cmd.Include) > 0 {
		return errors.New("--include cannot be combined with --pre-receive")
	}
	if remoteGitURL(cmd.Repo) && (cmd.Staged || cmd.Unstaged) {
		return errors.New("--staged and --unstaged require a local Git repository")
	}
	if len(cmd.Include) > 0 && (cmd.Staged || cmd.Unstaged) {
		return errors.New("--include requires a Git history scan; it cannot be combined with --staged or --unstaged")
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
	ignoreSource := source
	remote := remoteGitURL(source)
	if remote {
		ignoreSource = ""
	}
	cfg := initConfig(runtime, globals, &options.ScanFlags)
	initDiagnostics(runtime, &options.ScanFlags)

	// create runner
	filters, err := loadScanFilters(runtime, cfg, options.IgnoreFile, ignoreSource)
	if err != nil {
		runtime.fatal("unable to prepare scan", "error", err)
		return
	}
	runner, err := newScanPipeline(runtime, globals, &options.ScanFlags, cfg, scan.WithIgnoredFingerprints(filters.fingerprints...))
	if err != nil {
		runtime.fatal("unable to prepare scan", "error", err)
		return
	}

	var src sources.Source

	if options.PreReceive {
		updates, parseErr := sources.ParsePreReceiveInput(runtime.stdin)
		if parseErr != nil {
			runtime.fatal("could not read pre-receive input", "error", parseErr)
			return
		}
		logArgs := sources.PreReceiveLogArgs(updates, sources.NewGitCommitResolver(runtime.Context, source))
		if len(logArgs) == 0 {
			// Nothing to scan (e.g. only ref deletions). Report cleanly.
			runtime.Logger().Info("pre-receive: no new commits to scan")
			findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "git", source)
			findings.startScan(runtime)
			findingSummaryAndExit(runtime, pipeline.ScanSummary{}, runner.ValidationEnabled(), findings, options.ExitCode, start, nil)
			return
		}
		// Server-side hook scans have no remote to link findings to.
		src = &sources.Git{
			Logger:          runtime.Logger(),
			RepoPath:        source,
			Prefilter:       filters.shouldSkip,
			Platform:        scm.NoPlatform,
			MaxArchiveDepth: options.MaxArchiveDepth,
			LogOpts:         strings.Join(logArgs, " "),
		}
	} else if options.Unstaged || options.Staged {
		mode := sources.GitWorkingTree
		if options.Staged {
			mode = sources.GitStaged
		}
		// Local diffs have no committed revision to link to.
		src = &sources.Git{
			Logger:          runtime.Logger(),
			RepoPath:        source,
			Mode:            mode,
			Prefilter:       filters.shouldSkip,
			Platform:        scm.NoPlatform,
			MaxArchiveDepth: options.MaxArchiveDepth,
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
			Prefilter:       filters.shouldSkip,
			Platform:        resolvedPlatform,
			RemoteURL:       remoteURL,
			MaxArchiveDepth: options.MaxArchiveDepth,
			LogOpts:         options.LogOpts,
			Include:         options.Include,
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

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "git", source)
	findings.startScan(runtime)
	summary, err := runner.Scan(runtime.Context, src, findings.Add)
	if err != nil {
		runtime.Logger().Error("failed to scan Git repository", "error", err)
	}

	// When running as a pre-receive hook, print the custom error message
	// (with environment variables expanded) so the pushing client sees it.
	if options.PreReceive && options.PreReceiveError != "" && findings.Count() != 0 {
		fmt.Fprintln(runtime.stderr, os.ExpandEnv(options.PreReceiveError))
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
