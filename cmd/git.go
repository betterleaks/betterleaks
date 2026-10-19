package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/gogit"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

type GitCmd struct {
	ScanFlags       `embed:""`
	MaxArchiveDepth int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Allow scanning into nested archives up to this depth."`
	Token           string   `group:"source" help:"Token for an HTTPS clone (or the known host's GITHUB_TOKEN, GITLAB_TOKEN, HUGGINGFACE_TOKEN/HF_TOKEN)."`
	CloneRefs       []string `group:"source" name:"clone-ref" sep:"none" help:"Fetch an additional refs/... name or pattern with at most one '*' (repeatable; URL scans only)."`
	CloneAllRefs    bool     `group:"source" name:"clone-all-refs" help:"Fetch all advertised refs, including review refs (URL scans only)."`
	Platform        string   `group:"source" help:"Link platform: github, gitlab, azuredevops, gitea, bitbucket, unknown (auto), or none."`
	Since           string   `group:"source" help:"Minimum committer date, RFC3339 or YYYY-MM-DD (UTC)."`
	Until           string   `group:"source" help:"Maximum committer date, RFC3339 or YYYY-MM-DD (UTC)."`
	Author          string   `group:"source" help:"Go regular expression matching author name and email."`
	Committer       string   `group:"source" help:"Go regular expression matching committer name and email."`
	Revision        string   `group:"source" help:"Revision or range (A..B) from fetched or local history; does not fetch refs. Omit to scan HEAD and all non-note refs."`
	MaxCommits      int      `group:"source" name:"max-commits" help:"Limit selected commits in the history walk; zero is unlimited."`
	GitMaxBlobMiB   int      `group:"source" name:"git-max-blob-mib" default:"64" help:"Skip blobs larger than this many MiB, with a warning for each."`
	AllowExternal   bool     `group:"source" name:"allow-external-objects" help:"Read Git storage outside the repository (a .git file, commondir, or object alternate pointing elsewhere)."`
	Exclude         []string `group:"source" help:"Remove Git resources: history, merges, objects, unreachable-objects, commit-messages, notes, tag-messages, reflogs."`
	Include         []string `group:"source" help:"Add Git resources: history, merges, objects, unreachable-objects, commit-messages, notes, tag-messages, reflogs (default: history, without merge patches)."`
	Repo            string   `arg:"" optional:"" help:"Local repository or HTTP(S) repository URL to scan."`
}

func (cmd GitCmd) Validate() error {
	if err := cmd.ScanFlags.Validate(); err != nil {
		return err
	}
	src, err := cmd.gitSource()
	if err != nil {
		return err
	}
	return src.Validate()
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

	src, err := options.gitSource()
	if err != nil {
		runtime.fatal("invalid Git source", "error", err)
		return
	}
	src.Logger, src.Prefilter = runtime.Logger(), filters.shouldSkip

	findings := mustNewFindingCollector(runtime, &options.ScanFlags, globals.NoColor, start, cfg, "git", source)
	findings.startScan(runtime)
	summary, err := runner.Scan(runtime.Context, src, findings.Add)
	if errors.Is(err, gogit.ErrExternalStore) {
		runtime.Logger().Error("failed to scan Git repository; pass --allow-external-objects to read storage outside it", "error", err)
	} else if err != nil {
		runtime.Logger().Error("failed to scan Git repository", "error", err)
	}

	findingSummaryAndExit(runtime, summary, runner.ValidationEnabled(), findings, options.ExitCode, start, err)
}

// gitSource converts flags; gogit.Source.Validate checks the values.
//
//nolint:exhaustruct // Unset source options keep their documented defaults.
func (cmd GitCmd) gitSource() (*gogit.Source, error) {
	// A date-only --until includes that whole day.
	parseDate := func(value string, endOfDay bool) (*time.Time, error) {
		if value == "" {
			return nil, nil
		}
		if date, err := time.Parse(time.RFC3339, value); err == nil {
			return &date, nil
		}
		date, err := time.Parse(time.DateOnly, value)
		if err != nil {
			return nil, fmt.Errorf("invalid history date %q; use RFC3339 or YYYY-MM-DD", value)
		}
		if endOfDay {
			date = date.Add(24*time.Hour - time.Nanosecond)
		}
		return &date, nil
	}
	since, err := parseDate(cmd.Since, false)
	if err != nil {
		return nil, err
	}
	until, err := parseDate(cmd.Until, true)
	if err != nil {
		return nil, err
	}
	platform, err := scm.PlatformFromString(cmd.Platform)
	if err != nil {
		return nil, err
	}
	repo := cmd.Repo
	if repo == "" {
		repo = "."
	}
	url, token := "", cmd.Token
	if remoteGitURL(repo) {
		url, repo = repo, ""
		if token == "" {
			token = remoteGitToken(url)
		}
	} else if _, err := os.Stat(repo); err != nil {
		// Report a missing target here, before the ignore-file lookup stats it.
		if _, web := scm.ResolveRemoteURL(scm.UnknownPlatform, repo); web != "" {
			return nil, fmt.Errorf("SSH and git:// URLs are not supported; use an HTTPS URL such as %s", web)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("repository %q does not exist", repo)
		}
		return nil, err
	}
	return &gogit.Source{
		RepoPath: repo, URL: url, Token: token,
		CloneRefs: cmd.CloneRefs, CloneAllRefs: cmd.CloneAllRefs,
		Revision: cmd.Revision, Since: since, Until: until, Author: cmd.Author, Committer: cmd.Committer, MaxCount: cmd.MaxCommits,
		MaxBlobBytes: int64(cmd.GitMaxBlobMiB) << 20, Include: cmd.Include, Exclude: cmd.Exclude,
		AllowExternalObjects: cmd.AllowExternal, Platform: platform, MaxArchiveDepth: cmd.MaxArchiveDepth,
	}, nil
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
