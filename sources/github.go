package sources

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/semgroup"
	"github.com/google/go-github/v72/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// GitHub enumerates repositories via the GitHub API and delegates scanning
// to the Git source for each cloned repo.
type GitHub struct {
	// Auth
	Token string

	// Targets (at least one required)
	Repos []string // "owner/repo" format
	Orgs  []string
	Users []string

	// Filtering
	ExcludeRepos []string // glob patterns matched against "owner/repo"
	ExcludeForks bool

	// Scan config (passed through to Git/ParallelGit per repo)
	ShouldSkip      SkipFunc
	Sema            *semgroup.Group
	MaxArchiveDepth int
	Workers         int // git workers per repo (0 = single process)
	LogOpts         string

	// GitHub API
	BaseURL string // GitHub Enterprise base URL; empty = github.com

	// Actions scanning
	ScanActions bool
	Actions     ActionsOptions

	// Issue and PR scanning
	ScanIssues   bool
	ScanPRs      bool
	ScanComments bool
	IssueOpts    IssueOptions

	// Discussion scanning
	ScanDiscussions bool

	// Release scanning
	ScanReleases      bool
	ScanReleaseAssets bool // scan downloadable release assets (default true; disable with --no-release-artifacts)

	// Gist scanning (per-user, not per-repo)
	ScanGists bool

	// Single resource URL mode; when set, all other targets are ignored.
	URL string

	// Internal GraphQL client (initialized in Fragments).
	gqlClient *githubv4.Client

	// Telemetry counters populated during Fragments; safe for concurrent access.
	apiCalls     atomic.Int64 // total REST + GraphQL API calls made
	gqlRemaining atomic.Int64 // last known GraphQL points remaining (-1 = not yet observed)
	gqlResetAt   atomic.Int64 // unix timestamp of GraphQL rate limit reset (0 = unknown)
}

// ActionsOptions controls which workflow runs and artifacts to scan.
type ActionsOptions struct {
	Workflows     []string      // filter to specific workflow file names
	MaxAge        time.Duration // only scan runs newer than this
	MaxRuns       int           // max runs to fetch per repo (0 = 50)
	ScanArtifacts bool          // also download and scan artifacts
}

// IssueOptions controls issue, PR, and comment scanning.
type IssueOptions struct {
	MaxIssues   int       // max issues/PRs to fetch per repo (0 = no limit)
	MaxComments int       // max comments to fetch per issue or PR (0 = no limit)
	Since       time.Time // only scan items created on or after this time (zero = no lower bound)
	Until       time.Time // only scan items created before this time (zero = no upper bound)
}

// Fragments enumerates GitHub repos and scans each one.
func (s *GitHub) Fragments(ctx context.Context, yield FragmentsFunc) error {
	start := time.Now()
	client := s.newClient(ctx)
	s.gqlClient = s.newGraphQLClient(ctx)
	s.apiCalls.Store(0)
	s.gqlRemaining.Store(-1)
	s.gqlResetAt.Store(0)

	// URL mode: scan a single resource and return immediately.
	if s.URL != "" {
		return s.scanURL(ctx, client, yield)
	}

	repos, err := s.enumerateRepos(ctx, client)
	if err != nil {
		return fmt.Errorf("enumerate repos: %w", err)
	}

	logging.Info().
		Int("repos", len(repos)).
		Dur("enumeration_ms", time.Since(start)).
		Msg("GitHub repos to scan")

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, runtime.NumCPU()/2))

	for _, repo := range repos {
		g.Go(func() error {
			return s.scanRepo(gctx, client, repo, yield)
		})
	}

	// Gist scanning is user-level, not repo-level — runs alongside repo scans.
	if s.ScanGists {
		for _, user := range s.Users {
			g.Go(func() error {
				return s.scanUserGists(gctx, client, user, yield)
			})
		}
	}

	err = g.Wait()

	evt := logging.Info().
		Int("repos", len(repos)).
		Int64("api_calls_total", s.apiCalls.Load()).
		Dur("total_ms", time.Since(start))
	if remaining := s.gqlRemaining.Load(); remaining >= 0 {
		evt = evt.Int64("graphql_rate_limit_remaining", remaining)
		if reset := s.gqlResetAt.Load(); reset > 0 {
			evt = evt.Time("graphql_rate_limit_reset", time.Unix(reset, 0))
		}
	}
	evt.Msg("GitHub scan complete")

	return err
}

// enumerateRepos collects repos from explicit list, orgs, and users,
// deduplicates, and applies filters.
func (s *GitHub) enumerateRepos(ctx context.Context, client *github.Client) ([]*github.Repository, error) {
	seen := make(map[string]bool)
	var repos []*github.Repository

	add := func(r *github.Repository) {
		name := r.GetFullName()
		if seen[name] {
			return
		}
		if s.ExcludeForks && r.GetFork() {
			return
		}
		if s.isExcluded(name) {
			logging.Debug().Str("repo", name).Msg("excluding repo")
			return
		}
		seen[name] = true
		repos = append(repos, r)
	}

	// Explicit repos
	for _, slug := range s.Repos {
		owner, name, err := splitRepoSlug(slug)
		if err != nil {
			return nil, fmt.Errorf("invalid repo %q: %w", slug, err)
		}
		logging.Debug().Str("repo", slug).Msg("fetching repo metadata")
		repo, err := s.fetchRepo(ctx, client, owner, name)
		if err != nil {
			return nil, fmt.Errorf("fetch repo %s: %w", slug, err)
		}
		add(repo)
	}

	// Org repos
	for _, org := range s.Orgs {
		logging.Info().Str("org", org).Msg("enumerating org repos")
		orgRepos, err := s.listOrgRepos(ctx, client, org)
		if err != nil {
			return nil, fmt.Errorf("list org %s repos: %w", org, err)
		}
		for _, r := range orgRepos {
			add(r)
		}
	}

	// User repos
	for _, user := range s.Users {
		logging.Info().Str("user", user).Msg("enumerating user repos")
		userRepos, err := s.listUserRepos(ctx, client, user)
		if err != nil {
			return nil, fmt.Errorf("list user %s repos: %w", user, err)
		}
		for _, r := range userRepos {
			add(r)
		}
	}

	logging.Debug().Int("total", len(repos)).Msg("enumeration complete")
	return repos, nil
}

// scanRepo clones a single repo and delegates to the Git source.
// Git, Actions, and GraphQL issue/PR scanning run concurrently.
func (s *GitHub) scanRepo(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	name := repo.GetFullName()
	logger := logging.With().Str("repo", name).Logger()
	repoAttrs := s.repoAttributes(repo, "")
	repoStart := time.Now()

	if s.ShouldSkip != nil && s.ShouldSkip(s.repoAttributes(repo, ResourceGitHubRepo)) {
		logger.Debug().Msg("skipping repository based on prefilter")
		return nil
	}

	logger.Info().Msg("scanning repo")

	// Wrap yield to stamp GitHub metadata on every fragment from this repo.
	// ShouldSkip is checked here, after repo attrs are merged, so the full
	// attribute set (including github.repo, github.owner, etc.) is available
	// to the prefilter — not just the fragment-specific attrs set earlier.
	// Protected by a mutex because git, actions, and graphql run concurrently.
	var yieldMu sync.Mutex
	ghYield := func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range repoAttrs {
				if v == "" || fragment.Attr(k) != "" {
					continue
				}
				fragment.SetAttr(k, v)
			}
			// TODO update ShouldSkip so that we return a condition matched from CEL (if possible, large effort)
			if s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
				return nil
			}
		}
		yieldMu.Lock()
		defer yieldMu.Unlock()
		return yield(fragment, err)
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		gitStart := time.Now()
		if err := s.scanRepoGit(gctx, repo, ghYield); err != nil {
			logger.Error().Err(err).Msg("git scan failed")
			return fmt.Errorf("git scan %s: %w", name, err)
		}
		logger.Debug().Dur("git_ms", time.Since(gitStart)).Msg("git scan complete")
		return nil
	})

	if s.ScanActions {
		g.Go(func() error {
			actionsStart := time.Now()
			if err := s.scanActions(gctx, client, repo, ghYield); err != nil {
				logger.Error().Err(err).Msg("actions scan failed")
				return fmt.Errorf("actions scan %s: %w", name, err)
			}
			logger.Debug().Dur("actions_ms", time.Since(actionsStart)).Msg("actions scan complete")
			return nil
		})
	}

	if s.ScanIssues || s.ScanPRs || s.ScanComments {
		g.Go(func() error {
			logger.Info().
				Bool("issues", s.ScanIssues).
				Bool("prs", s.ScanPRs).
				Bool("comments", s.ScanComments).
				Int("issues_max", s.IssueOpts.MaxIssues).
				Int("comments_max", s.IssueOpts.MaxComments).
				Msg("scanning issues, prs, and comments")
			issuesStart := time.Now()
			if err := s.scanIssuesAndPRsGraphQL(gctx, repo, ghYield); err != nil {
				logger.Error().Err(err).Msg("issues/prs scan failed")
				return fmt.Errorf("issues/prs scan %s: %w", name, err)
			}
			logger.Debug().Dur("issues_prs_ms", time.Since(issuesStart)).Msg("issues/prs scan complete")
			return nil
		})
	}

	if s.ScanDiscussions {
		g.Go(func() error {
			discussionsStart := time.Now()
			if err := s.scanDiscussions(gctx, repo, ghYield); err != nil {
				logger.Error().Err(err).Msg("discussions scan failed")
				return fmt.Errorf("discussions scan %s: %w", name, err)
			}
			logger.Debug().Dur("discussions_ms", time.Since(discussionsStart)).Msg("discussions scan complete")
			return nil
		})
	}

	if s.ScanReleases {
		g.Go(func() error {
			releasesStart := time.Now()
			if err := s.scanReleases(gctx, client, repo, ghYield); err != nil {
				logger.Error().Err(err).Msg("releases scan failed")
				return fmt.Errorf("releases scan %s: %w", name, err)
			}
			logger.Debug().Dur("releases_ms", time.Since(releasesStart)).Msg("releases scan complete")
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		logger.Warn().Err(err).Dur("total_ms", time.Since(repoStart)).Msg("repo scan completed with errors")
		return err
	}
	logger.Info().Dur("total_ms", time.Since(repoStart)).Msg("repo scan complete")
	return nil
}

func (s *GitHub) repoAttributes(repo *github.Repository, resource string) map[string]string {
	attrs := map[string]string{
		AttrGitHubOwner:      repo.GetOwner().GetLogin(),
		AttrGitHubOwnerType:  repo.GetOwner().GetType(),
		AttrGitHubRepo:       repo.GetName(),
		AttrGitHubRepoURL:    repo.GetHTMLURL(),
		AttrGitHubVisibility: repo.GetVisibility(),
	}
	if resource != "" {
		attrs[AttrResource] = resource
	}
	return attrs
}

// fetchRepo gets a single repo by owner/name with rate limit retry.
func (s *GitHub) fetchRepo(ctx context.Context, client *github.Client, owner, name string) (*github.Repository, error) {
	var repo *github.Repository
	err := s.withRetry(ctx, func() error {
		var err error
		repo, _, err = client.Repositories.Get(ctx, owner, name)
		return err
	})
	return repo, err
}

// listOrgRepos paginates all repos for an organization.
func (s *GitHub) listOrgRepos(ctx context.Context, client *github.Client, org string) ([]*github.Repository, error) {
	var all []*github.Repository
	opts := &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		var repos []*github.Repository
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			repos, resp, err = client.Repositories.ListByOrg(ctx, org, opts)
			return err
		})
		if err != nil {
			return all, err
		}
		all = append(all, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

// listUserRepos paginates all repos for a user.
func (s *GitHub) listUserRepos(ctx context.Context, client *github.Client, user string) ([]*github.Repository, error) {
	var all []*github.Repository
	opts := &github.RepositoryListByUserOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		var repos []*github.Repository
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			repos, resp, err = client.Repositories.ListByUser(ctx, user, opts)
			return err
		})
		if err != nil {
			return all, err
		}
		all = append(all, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}
	return all, nil
}

// isExcluded checks if a repo full name matches any exclusion glob.
func (s *GitHub) isExcluded(fullName string) bool {
	for _, pattern := range s.ExcludeRepos {
		if matched, _ := filepath.Match(pattern, fullName); matched {
			return true
		}
	}
	return false
}

// splitRepoSlug splits "owner/repo" into owner and repo.
func splitRepoSlug(slug string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("expected owner/repo format, got %q", slug)
	}
	return owner, repo, nil
}

// withRetry retries an API call up to 3 times on rate limit errors.
// It also respects the shared rate-limit governor.
func (s *GitHub) withRetry(ctx context.Context, fn func() error) error {
	const maxRetries = 3
	for attempt := range maxRetries {
		if err := ghAwaitRateLimit(ctx); err != nil {
			return err
		}
		err := fn()
		s.apiCalls.Add(1)
		if err == nil {
			return nil
		}

		var rateLimitErr *github.RateLimitError
		if errors.As(err, &rateLimitErr) && attempt < maxRetries-1 {
			wait := time.Until(rateLimitErr.Rate.Reset.Time) + time.Second
			if wait < 0 {
				wait = time.Second
			}
			ghSetRateLimitPause(wait)
			logging.Warn().Dur("wait", wait).Int("attempt", attempt+1).Msg("GitHub rate limit hit, sleeping")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
				continue
			}
		}
		return err
	}
	return nil // unreachable
}

// newClient creates a GitHub API client with optional token auth and GHE support.
func (s *GitHub) newClient(ctx context.Context) *github.Client {
	var httpClient *http.Client
	if s.Token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: s.Token})
		httpClient = oauth2.NewClient(ctx, ts)
	}
	client := github.NewClient(httpClient)
	if s.BaseURL != "" {
		c, err := client.WithEnterpriseURLs(s.BaseURL, s.BaseURL)
		if err != nil {
			logging.Warn().Err(err).Str("url", s.BaseURL).Msg("could not configure GHE URL, using github.com")
		} else {
			client = c
		}
	}
	return client
}

// scanRepoGit clones and scans a repo's git history.
func (s *GitHub) scanRepoGit(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	name := repo.GetFullName()
	logger := logging.With().Str("repo", name).Logger()
	cloneStart := time.Now()

	tmpDir, err := os.MkdirTemp("", "betterleaks-github-*")
	if err != nil {
		logger.Error().Err(err).Msg("could not create temp dir")
		return nil
	}
	defer func() {
		logger.Debug().Str("dir", tmpDir).Msg("cleaning up cloned repo")
		os.RemoveAll(tmpDir)
	}()

	logger.Debug().Str("dir", tmpDir).Msg("cloning repo")
	if err := s.cloneRepo(ctx, repo, tmpDir); err != nil {
		return err
	}
	logger.Debug().Dur("clone_ms", time.Since(cloneStart)).Msg("clone complete")

	var src Source
	if s.Workers > 0 {
		logger.Debug().Int("workers", s.Workers).Msg("using parallel git source")
		src = &ParallelGit{
			RepoPath:        tmpDir,
			ShouldSkip:      s.ShouldSkip,
			Platform:        scm.GitHubPlatform,
			RemoteURL:       repo.GetHTMLURL(),
			Sema:            s.Sema,
			MaxArchiveDepth: s.MaxArchiveDepth,
			LogOpts:         s.LogOpts,
			Workers:         s.Workers,
		}
	} else {
		gitCmd, err := NewGitLogCmdContext(ctx, tmpDir, s.LogOpts)
		if err != nil {
			return err
		}
		src = &Git{
			Cmd:             gitCmd,
			ShouldSkip:      s.ShouldSkip,
			Platform:        scm.GitHubPlatform,
			RemoteURL:       repo.GetHTMLURL(),
			Sema:            s.Sema,
			MaxArchiveDepth: s.MaxArchiveDepth,
		}
	}

	gitStart := time.Now()
	logger.Debug().Msg("starting git scan")
	scanErr := src.Fragments(ctx, yield)
	logger.Debug().Dur("git_ms", time.Since(gitStart)).Msg("git scan complete")
	return scanErr
}

// cloneRepo performs a bare git clone with token auth delivered via
// http.extraheader so that credentials never appear in process arguments
// (visible in /proc/PID/cmdline) or in git error output.
// Uses a broad refspec (+refs/*:refs/remotes/origin/*) to fetch all refs
// including PR heads, tags, and non-standard refs so that git log --all
// can traverse the complete commit graph.
func (s *GitHub) cloneRepo(ctx context.Context, repo *github.Repository, dest string) error {
	cloneURL := repo.GetCloneURL()

	args := []string{"clone", "--bare", "--quiet",
		"-c", "remote.origin.fetch=+refs/*:refs/remotes/origin/*",
	}
	if s.Token != "" {
		// Deliver credentials via http.extraheader instead of embedding
		// them in the URL, which would expose the token in process args
		// and potentially in git error messages.
		cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + s.Token))
		args = append(args, "-c", "http.extraheader=Authorization: basic "+cred)
	}
	args = append(args, cloneURL, dest)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitConfigIsolationEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	_ = output
	return nil
}

// ============ Actions scan path ============

// scanActions scans workflow run logs (and optionally artifacts) for a repo.
func (s *GitHub) scanActions(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	logger := logging.With().Str("repo", repo.GetFullName()).Logger()
	start := time.Now()
	logger.Info().Msg("scanning actions")

	runs, err := s.listWorkflowRuns(ctx, client, owner, repoName)
	if err != nil {
		return fmt.Errorf("list workflow runs: %w", err)
	}
	logger.Debug().Int("runs", len(runs)).Dur("list_runs_ms", time.Since(start)).Msg("workflow runs to scan")

	for _, run := range runs {
		runID := run.GetID()
		runLogger := logger.With().Int64("run_id", runID).Str("name", run.GetName()).Logger()

		// Scan workflow run logs (delivered as a zip of per-job log files).
		runLogger.Debug().Msg("downloading run logs")
		if err := s.scanRunLogs(ctx, client, owner, repoName, run, yield); err != nil {
			if isGitHubGone(err) {
				runLogger.Debug().Err(err).Msg("run logs expired or unavailable")
			} else {
				runLogger.Error().Err(err).Msg("could not scan run logs")
			}
		}

		// Scan artifacts if requested.
		if s.Actions.ScanArtifacts {
			runLogger.Debug().Msg("scanning run artifacts")
			if err := s.scanRunArtifacts(ctx, client, owner, repoName, run, yield); err != nil {
				runLogger.Error().Err(err).Msg("could not scan run artifacts")
			}
		}
	}

	logger.Debug().Int("runs", len(runs)).Dur("actions_ms", time.Since(start)).Msg("actions scan complete")
	return nil
}

// listWorkflowRuns lists runs for a repo, respecting MaxRuns, MaxAge, and Workflows filters.
func (s *GitHub) listWorkflowRuns(ctx context.Context, client *github.Client, owner, repo string) ([]*github.WorkflowRun, error) {
	maxRuns := s.Actions.MaxRuns
	if maxRuns == 0 {
		maxRuns = 50
	}

	opts := &github.ListWorkflowRunsOptions{
		ListOptions: github.ListOptions{PerPage: min(100, maxRuns)},
	}
	if s.Actions.MaxAge > 0 {
		cutoff := time.Now().Add(-s.Actions.MaxAge).UTC().Format("2006-01-02")
		opts.Created = ">=" + cutoff
	}

	// If specific workflows are requested, fetch runs for each and merge.
	// Copy opts per workflow so paginateWorkflowRuns' Page mutation
	// doesn't carry over to the next workflow.
	if len(s.Actions.Workflows) > 0 {
		var all []*github.WorkflowRun
		for _, wf := range s.Actions.Workflows {
			wfOpts := *opts // copy to avoid Page mutation leaking across workflows
			runs, err := s.paginateWorkflowRuns(ctx, client, owner, repo, wf, &wfOpts, maxRuns-len(all))
			if err != nil {
				return all, err
			}
			all = append(all, runs...)
			if len(all) >= maxRuns {
				break
			}
		}
		return all, nil
	}

	return s.paginateWorkflowRuns(ctx, client, owner, repo, "", opts, maxRuns)
}

func (s *GitHub) paginateWorkflowRuns(ctx context.Context, client *github.Client, owner, repo, workflow string, opts *github.ListWorkflowRunsOptions, limit int) ([]*github.WorkflowRun, error) {
	var all []*github.WorkflowRun
	for {
		var result *github.WorkflowRuns
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			if workflow != "" {
				result, resp, err = client.Actions.ListWorkflowRunsByFileName(ctx, owner, repo, workflow, opts)
			} else {
				result, resp, err = client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
			}
			return err
		})
		if err != nil {
			return all, err
		}
		all = append(all, result.WorkflowRuns...)
		if len(all) >= limit || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// scanRunLogs downloads the logs zip for a workflow run and scans it.
func (s *GitHub) scanRunLogs(ctx context.Context, client *github.Client, owner, repo string, run *github.WorkflowRun, yield FragmentsFunc) error {
	var logURL *url.URL
	err := s.withRetry(ctx, func() error {
		var err error
		logURL, _, err = client.Actions.GetWorkflowRunLogs(ctx, owner, repo, run.GetID(), 3)
		return err
	})
	if err != nil {
		return err
	}

	return s.downloadAndScanZip(ctx, logURL, run, "actions/logs", yield)
}

// scanRunArtifacts lists and scans all artifacts for a workflow run.
func (s *GitHub) scanRunArtifacts(ctx context.Context, client *github.Client, owner, repo string, run *github.WorkflowRun, yield FragmentsFunc) error {
	opts := &github.ListOptions{PerPage: 100}
	for {
		var artifacts *github.ArtifactList
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			artifacts, resp, err = client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, run.GetID(), opts)
			return err
		})
		if err != nil {
			return err
		}

		for _, artifact := range artifacts.Artifacts {
			if artifact.GetExpired() {
				continue
			}
			logger := logging.With().
				Str("artifact", artifact.GetName()).
				Int64("run_id", run.GetID()).Logger()
			logger.Debug().Msg("downloading artifact")

			var artifactURL *url.URL
			err := s.withRetry(ctx, func() error {
				var err error
				artifactURL, _, err = client.Actions.DownloadArtifact(ctx, owner, repo, artifact.GetID(), 3)
				return err
			})
			if err != nil {
				logger.Error().Err(err).Msg("could not get artifact download URL")
				continue
			}

			pathPrefix := fmt.Sprintf("actions/artifacts/%s", artifact.GetName())
			if err := s.downloadAndScanZip(ctx, artifactURL, run, pathPrefix, yield); err != nil {
				logger.Error().Err(err).Msg("could not scan artifact")
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
}

// downloadAndScanZip downloads a zip from a URL into a temp file, then scans
// it using the File source (which handles zip extraction natively).
func (s *GitHub) downloadAndScanZip(ctx context.Context, zipURL *url.URL, run *github.WorkflowRun, pathPrefix string, yield FragmentsFunc) error {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL.String(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}

	tmp, err := os.CreateTemp("", "betterleaks-actions-*.zip")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		logging.Debug().Str("path", tmp.Name()).Msg("cleaning up actions zip")
		os.Remove(tmp.Name())
	}()

	bytesWritten, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return fmt.Errorf("download zip: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	runIDStr := strconv.FormatInt(run.GetID(), 10)
	zipPath := pathPrefix + "/run_" + runIDStr + ".zip"

	// Actions metadata to stamp on every fragment from this zip.
	actionsAttrs := map[string]string{
		AttrGitHubActionsRunID:   runIDStr,
		AttrGitHubActionsRunName: run.GetName(),
		AttrGitHubActionsRunURL:  run.GetHTMLURL(),
		AttrGitHubActionsEvent:   run.GetEvent(),
		AttrResource:             ResourceGitHubActions,
	}

	file := &File{
		Content:         tmp,
		Path:            zipPath,
		MaxArchiveDepth: max(1, s.MaxArchiveDepth), // must be >= 1 to extract the zip
		ShouldSkip:      s.ShouldSkip,
	}

	err = file.Fragments(ctx, func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range actionsAttrs {
				// AttrResource: outer wins (actions, not file).
				// Everything else: don't clobber if already set.
				if k == AttrResource || fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
		}
		return yield(fragment, err)
	})
	logging.Debug().
		Int64("run_id", run.GetID()).
		Str("path_prefix", pathPrefix).
		Int64("bytes", bytesWritten).
		Dur("zip_scan_ms", time.Since(start)).
		Msg("actions zip scan complete")
	return err
}

// isGitHubGone checks if an error is a GitHub 404 or 410 (expired/deleted logs, artifacts, etc.).
func isGitHubGone(err error) bool {
	if err == nil {
		return false
	}
	// go-github returns *ErrorResponse for API errors.
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		code := ghErr.Response.StatusCode
		return code == http.StatusNotFound || code == http.StatusGone
	}
	// GetWorkflowRunLogs returns a plain fmt.Errorf for non-302 status codes.
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "410")
}

type ghPageInfo struct {
	HasNextPage bool
	EndCursor   githubv4.String
}

type ghRateLimit struct {
	Remaining int
	ResetAt   time.Time
}

type ghActor struct {
	Login string
}

// ghComment is the shared comment shape used by issue comments,
// PR issue comments, and review thread comments.
type ghComment struct {
	DatabaseId int64
	Body       string
	Url        string
	CreatedAt  time.Time
	Author     ghActor
}

type ghCommentConnection struct {
	Nodes    []ghComment
	PageInfo ghPageInfo
}

// ghIssueNode is an issue node with first page of comments inlined.
type ghIssueNode struct {
	Number    int
	Title     string
	Body      string
	Url       string
	Author    ghActor
	CreatedAt time.Time
	Comments  ghCommentConnection `graphql:"comments(first: $commentsFirst)"`
}

// ghReviewThreadNode is a review thread inlined under a PR, with comments inlined too.
type ghReviewThreadNode struct {
	Id       githubv4.ID
	Comments ghCommentConnection `graphql:"comments(first: $commentsFirst)"`
}

type ghReviewThreadConnection struct {
	Nodes    []ghReviewThreadNode
	PageInfo ghPageInfo
}

// ghPRNode is a PR node with first page of issue-style comments
// AND first page of review threads inlined.
type ghPRNode struct {
	Number        int
	Title         string
	Body          string
	Url           string
	Author        ghActor
	CreatedAt     time.Time
	Comments      ghCommentConnection      `graphql:"comments(first: $commentsFirst)"`
	ReviewThreads ghReviewThreadConnection `graphql:"reviewThreads(first: $threadsFirst)"`
}

// ghRepoScanQuery is the unified per-page query.
// Fetches one page of issues AND one page of PRs in a single round trip.
type ghRepoScanQuery struct {
	Repository struct {
		Issues struct {
			Nodes    []ghIssueNode
			PageInfo ghPageInfo
		} `graphql:"issues(first: $issuesFirst, after: $issuesAfter, orderBy: {field: CREATED_AT, direction: DESC})"`
		PullRequests struct {
			Nodes    []ghPRNode
			PageInfo ghPageInfo
		} `graphql:"pullRequests(first: $prsFirst, after: $prsAfter, orderBy: {field: CREATED_AT, direction: DESC})"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

// ghIssueCommentsTailQuery fetches more comments for one issue when the first page didn't cover all.
type ghIssueCommentsTailQuery struct {
	Repository struct {
		Issue struct {
			Comments ghCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"issue(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

// ghPRCommentsTailQuery fetches more issue-style comments for one PR.
type ghPRCommentsTailQuery struct {
	Repository struct {
		PullRequest struct {
			Comments ghCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

// ghPRReviewThreadsTailQuery fetches more review threads for one PR (when >50 threads).
type ghPRReviewThreadsTailQuery struct {
	Repository struct {
		PullRequest struct {
			ReviewThreads ghReviewThreadConnection `graphql:"reviewThreads(first: $threadsFirst, after: $threadsAfter)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

// ghThreadCommentsTailQuery fetches more comments for one review thread (when a thread has >50 comments).
type ghThreadCommentsTailQuery struct {
	Node struct {
		Thread struct {
			Comments ghCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"... on PullRequestReviewThread"`
	} `graphql:"node(id: $threadId)"`
	RateLimit ghRateLimit
}

var (
	ghRateLimitMu     sync.RWMutex
	ghRateLimitResume time.Time
)

func ghAwaitRateLimit(ctx context.Context) error {
	ghRateLimitMu.RLock()
	wait := time.Until(ghRateLimitResume)
	ghRateLimitMu.RUnlock()
	if wait <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

func ghSetRateLimitPause(d time.Duration) {
	ghRateLimitMu.Lock()
	defer ghRateLimitMu.Unlock()
	resume := time.Now().Add(d)
	if resume.After(ghRateLimitResume) {
		ghRateLimitResume = resume
	}
}

// newGraphQLClient constructs a githubv4 client with optional token auth and GHE support.
func (s *GitHub) newGraphQLClient(ctx context.Context) *githubv4.Client {
	var httpClient *http.Client
	if s.Token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: s.Token})
		httpClient = oauth2.NewClient(ctx, ts)
	}
	if s.BaseURL == "" {
		return githubv4.NewClient(httpClient)
	}
	// GHE: REST is at <host>/api/v3, GraphQL is at <host>/api/graphql.
	u, err := url.Parse(s.BaseURL)
	if err != nil {
		logging.Warn().Err(err).Str("url", s.BaseURL).Msg("could not parse GHE URL for GraphQL, falling back to github.com")
		return githubv4.NewClient(httpClient)
	}
	before, _ := strings.CutSuffix(u.Path, "/api/v3")
	u.Path = before + "/api/graphql"
	return githubv4.NewEnterpriseClient(u.String(), httpClient)
}

// gqlRequestTimeout is the per-request deadline for a single GraphQL HTTP call.
// oauth2/githubv4 use http.DefaultTransport which has no timeout; without this
// GitHub can hold a connection open indefinitely when throttling.
const gqlRequestTimeout = 15 * time.Second

// gqlQuery wraps every GraphQL call with rate-limit handling and transient-error retries.
func (s *GitHub) gqlQuery(ctx context.Context, q any, vars map[string]any, rl *ghRateLimit) error {
	const maxAttempts = 4
	for attempt := range maxAttempts {
		if err := ghAwaitRateLimit(ctx); err != nil {
			return err
		}

		// Apply a per-request deadline so a hung connection is detected and
		// retried rather than blocking the goroutine forever.
		reqCtx, cancel := context.WithTimeout(ctx, gqlRequestTimeout)
		err := s.gqlClient.Query(reqCtx, q, vars)
		cancel()
		s.apiCalls.Add(1)

		if err == nil {
			if rl != nil {
				s.gqlRemaining.Store(int64(rl.Remaining))
				s.gqlResetAt.Store(rl.ResetAt.Unix())
				// Proactive backoff if we're running low on quota.
				if rl.Remaining > 0 && rl.Remaining < 5 {
					pause := time.Until(rl.ResetAt) + 2*time.Second
					if pause > 0 {
						ghSetRateLimitPause(pause)
					}
				}
			}
			return nil
		}

		// If the parent context was cancelled, propagate immediately.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		msg := err.Error()
		isRateLimit := strings.Contains(msg, "rate limit") || strings.Contains(msg, "secondary rate limit")
		isTimeout := errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "context deadline exceeded")
		isTransient := strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection refused")

		if isRateLimit {
			ghSetRateLimitPause(60 * time.Second)
			continue
		}
		if attempt < maxAttempts-1 && (isTimeout || isTransient) {
			backoff := time.Duration(1<<attempt) * time.Second
			logging.Warn().
				Str("error", msg).
				Int("attempt", attempt+1).
				Dur("backoff", backoff).
				Msg("transient GraphQL error, retrying")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}
		return err
	}
	return fmt.Errorf("graphql query failed after %d attempts", maxAttempts)
}

// scanIssuesAndPRsGraphQL scans issues, PRs, and comments via the GitHub GraphQL API.
func (s *GitHub) scanIssuesAndPRsGraphQL(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	logger := logging.With().Str("repo", repo.GetFullName()).Logger()
	start := time.Now()

	var (
		issuesAfter  *githubv4.String
		prsAfter     *githubv4.String
		issuesDone   = !s.ScanIssues && !s.ScanComments
		prsDone      = !s.ScanPRs && !s.ScanComments
		issueCount   int
		prCount      int
		commentCount int
	)

	for !issuesDone || !prsDone {
		if s.IssueOpts.MaxIssues > 0 && issueCount+prCount >= s.IssueOpts.MaxIssues {
			break
		}

		vars := map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"issuesFirst":   githubv4.Int(50),
			"issuesAfter":   issuesAfter,
			"prsFirst":      githubv4.Int(25),
			"prsAfter":      prsAfter,
			"commentsFirst": githubv4.Int(50),
			"threadsFirst":  githubv4.Int(50),
		}
		// If one side is done, ask for zero to keep the query well-formed.
		if issuesDone {
			vars["issuesFirst"] = githubv4.Int(0)
		}
		if prsDone {
			vars["prsFirst"] = githubv4.Int(0)
		}

		var q ghRepoScanQuery
		if err := s.gqlQuery(ctx, &q, vars, &q.RateLimit); err != nil {
			return fmt.Errorf("graphql repo scan: %w", err)
		}

		// Process issues from this page.
		// Results are ordered CREATED_AT DESC, so once we see an issue
		// older than Since we can stop paginating.
		if !issuesDone {
			for _, issue := range q.Repository.Issues.Nodes {
				if s.IssueOpts.MaxIssues > 0 && issueCount+prCount >= s.IssueOpts.MaxIssues {
					break
				}
				if !s.IssueOpts.Since.IsZero() && issue.CreatedAt.Before(s.IssueOpts.Since) {
					issuesDone = true
					break
				}
				if !s.IssueOpts.Until.IsZero() && !issue.CreatedAt.Before(s.IssueOpts.Until) {
					// Newer than until cutoff — skip but keep paginating.
					continue
				}
				if err := s.emitIssueAndComments(ctx, owner, name, issue, &commentCount, yield); err != nil {
					return err
				}
				issueCount++
			}
			if !issuesDone {
				if !q.Repository.Issues.PageInfo.HasNextPage {
					issuesDone = true
				} else {
					issuesAfter = githubv4.NewString(q.Repository.Issues.PageInfo.EndCursor)
				}
			}
		}

		// Process PRs from this page (same date-range logic as issues).
		if !prsDone {
			for _, pr := range q.Repository.PullRequests.Nodes {
				if s.IssueOpts.MaxIssues > 0 && issueCount+prCount >= s.IssueOpts.MaxIssues {
					break
				}
				if !s.IssueOpts.Since.IsZero() && pr.CreatedAt.Before(s.IssueOpts.Since) {
					prsDone = true
					break
				}
				if !s.IssueOpts.Until.IsZero() && !pr.CreatedAt.Before(s.IssueOpts.Until) {
					continue
				}
				if err := s.emitPRAndComments(ctx, owner, name, pr, &commentCount, yield); err != nil {
					return err
				}
				prCount++
			}
			if !prsDone {
				if !q.Repository.PullRequests.PageInfo.HasNextPage {
					prsDone = true
				} else {
					prsAfter = githubv4.NewString(q.Repository.PullRequests.PageInfo.EndCursor)
				}
			}
		}
	}

	logger.Debug().
		Int("issues", issueCount).
		Int("prs", prCount).
		Int("comments", commentCount).
		Dur("issues_prs_ms", time.Since(start)).
		Msg("graphql issues/prs scan complete")
	return nil
}

func (s *GitHub) emitIssueAndComments(ctx context.Context, owner, name string, issue ghIssueNode, totalComments *int, yield FragmentsFunc) error {
	if s.ScanIssues && (issue.Title != "" || issue.Body != "") {
		frag := Fragment{Raw: strings.TrimSpace(issue.Title + "\n" + issue.Body)}
		frag.SetAttr(AttrURL, issue.Url)
		frag.SetAttr(AttrResource, ResourceGitHubIssue)
		frag.SetAttr(AttrGitHubIssueNumber, strconv.Itoa(issue.Number))
		if err := yield(frag, nil); err != nil {
			return err
		}
	}

	if !s.ScanComments {
		return nil
	}

	// Per-issue comment counter (MaxComments applies per item, not globally).
	var itemComments int

	// First page of comments (already in hand).
	if err := s.emitCommentNodes(issue.Comments.Nodes, issue.Url, "", strconv.Itoa(issue.Number), &itemComments, yield); err != nil {
		return err
	}

	// Tail pages.
	cursor := issue.Comments.PageInfo.EndCursor
	hasMore := issue.Comments.PageInfo.HasNextPage
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && itemComments >= s.IssueOpts.MaxComments {
			break
		}
		var tail ghIssueCommentsTailQuery
		vars := map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"number":        githubv4.Int(issue.Number),
			"commentsFirst": githubv4.Int(50),
			"commentsAfter": githubv4.NewString(cursor),
		}
		if err := s.gqlQuery(ctx, &tail, vars, &tail.RateLimit); err != nil {
			return fmt.Errorf("issue %d comments tail: %w", issue.Number, err)
		}
		if err := s.emitCommentNodes(tail.Repository.Issue.Comments.Nodes, issue.Url, "", strconv.Itoa(issue.Number), &itemComments, yield); err != nil {
			return err
		}
		hasMore = tail.Repository.Issue.Comments.PageInfo.HasNextPage
		cursor = tail.Repository.Issue.Comments.PageInfo.EndCursor
	}
	*totalComments += itemComments
	return nil
}

func (s *GitHub) emitPRAndComments(ctx context.Context, owner, name string, pr ghPRNode, totalComments *int, yield FragmentsFunc) error {
	if s.ScanPRs && (pr.Title != "" || pr.Body != "") {
		frag := Fragment{Raw: strings.TrimSpace(pr.Title + "\n" + pr.Body)}
		frag.SetAttr(AttrURL, pr.Url)
		frag.SetAttr(AttrResource, ResourceGitHubPR)
		frag.SetAttr(AttrGitHubPRNumber, strconv.Itoa(pr.Number))
		if err := yield(frag, nil); err != nil {
			return err
		}
	}

	if !s.ScanComments {
		return nil
	}

	// Per-PR comment counter (MaxComments applies per item, not globally).
	var itemComments int
	prNumStr := strconv.Itoa(pr.Number)

	// Issue-style PR comments: first page in hand, then tail.
	if err := s.emitCommentNodes(pr.Comments.Nodes, pr.Url, prNumStr, "", &itemComments, yield); err != nil {
		return err
	}
	cursor := pr.Comments.PageInfo.EndCursor
	hasMore := pr.Comments.PageInfo.HasNextPage
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && itemComments >= s.IssueOpts.MaxComments {
			break
		}
		var tail ghPRCommentsTailQuery
		vars := map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"number":        githubv4.Int(pr.Number),
			"commentsFirst": githubv4.Int(50),
			"commentsAfter": githubv4.NewString(cursor),
		}
		if err := s.gqlQuery(ctx, &tail, vars, &tail.RateLimit); err != nil {
			return fmt.Errorf("pr %d comments tail: %w", pr.Number, err)
		}
		if err := s.emitCommentNodes(tail.Repository.PullRequest.Comments.Nodes, pr.Url, prNumStr, "", &itemComments, yield); err != nil {
			return err
		}
		hasMore = tail.Repository.PullRequest.Comments.PageInfo.HasNextPage
		cursor = tail.Repository.PullRequest.Comments.PageInfo.EndCursor
	}

	// Review thread comments: first page of threads in hand.
	// Each thread also has its first page of comments inline.
	threads := pr.ReviewThreads.Nodes
	threadsCursor := pr.ReviewThreads.PageInfo.EndCursor
	threadsHasMore := pr.ReviewThreads.PageInfo.HasNextPage
	for {
		for _, thread := range threads {
			if err := s.emitCommentNodes(thread.Comments.Nodes, pr.Url, prNumStr, "", &itemComments, yield); err != nil {
				return err
			}
			// Tail-paginate this thread's comments if needed.
			if thread.Comments.PageInfo.HasNextPage {
				if err := s.tailThreadComments(ctx, pr.Url, prNumStr, thread.Id, thread.Comments.PageInfo.EndCursor, &itemComments, yield); err != nil {
					return err
				}
			}
		}
		if !threadsHasMore {
			break
		}
		// Fetch next page of threads for this PR.
		var tail ghPRReviewThreadsTailQuery
		vars := map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"number":        githubv4.Int(pr.Number),
			"threadsFirst":  githubv4.Int(50),
			"threadsAfter":  githubv4.NewString(threadsCursor),
			"commentsFirst": githubv4.Int(50),
		}
		if err := s.gqlQuery(ctx, &tail, vars, &tail.RateLimit); err != nil {
			return fmt.Errorf("pr %d threads tail: %w", pr.Number, err)
		}
		threads = tail.Repository.PullRequest.ReviewThreads.Nodes
		threadsHasMore = tail.Repository.PullRequest.ReviewThreads.PageInfo.HasNextPage
		threadsCursor = tail.Repository.PullRequest.ReviewThreads.PageInfo.EndCursor
	}
	*totalComments += itemComments
	return nil
}

func (s *GitHub) tailThreadComments(ctx context.Context, prURL, prNumStr string, threadId githubv4.ID, cursor githubv4.String, commentCount *int, yield FragmentsFunc) error {
	hasMore := true
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && *commentCount >= s.IssueOpts.MaxComments {
			return nil
		}
		var tail ghThreadCommentsTailQuery
		vars := map[string]any{
			"threadId":      threadId,
			"commentsFirst": githubv4.Int(50),
			"commentsAfter": githubv4.NewString(cursor),
		}
		if err := s.gqlQuery(ctx, &tail, vars, &tail.RateLimit); err != nil {
			return fmt.Errorf("thread comments tail: %w", err)
		}
		if err := s.emitCommentNodes(tail.Node.Thread.Comments.Nodes, prURL, prNumStr, "", commentCount, yield); err != nil {
			return err
		}
		hasMore = tail.Node.Thread.Comments.PageInfo.HasNextPage
		cursor = tail.Node.Thread.Comments.PageInfo.EndCursor
	}
	return nil
}

// emitCommentNodes yields one Fragment per comment.
// Either prNum or issueNum should be set; pass "" for the unused one.
func (s *GitHub) emitCommentNodes(comments []ghComment, parentURL, prNum, issueNum string, count *int, yield FragmentsFunc) error {
	for _, c := range comments {
		if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
			return nil
		}
		if c.Body == "" {
			continue
		}
		if !s.IssueOpts.Since.IsZero() && c.CreatedAt.Before(s.IssueOpts.Since) {
			continue
		}
		if !s.IssueOpts.Until.IsZero() && !c.CreatedAt.Before(s.IssueOpts.Until) {
			continue
		}
		(*count)++

		frag := Fragment{Raw: c.Body}
		u := c.Url
		if u == "" {
			u = parentURL
		}
		frag.SetAttr(AttrURL, u)
		frag.SetAttr(AttrResource, ResourceGitHubComment)
		frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(c.DatabaseId, 10))
		if prNum != "" {
			frag.SetAttr(AttrGitHubPRNumber, prNum)
		}
		if issueNum != "" {
			frag.SetAttr(AttrGitHubIssueNumber, issueNum)
		}
		if err := yield(frag, nil); err != nil {
			return err
		}
	}
	return nil
}

// ============ Releases scan path ============

// scanReleases scans GitHub Releases for a repo via the REST API.
func (s *GitHub) scanReleases(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	logger := logging.With().Str("repo", repo.GetFullName()).Logger()
	logger.Info().Msg("scanning releases")

	opts := &github.ListOptions{PerPage: 100}
	var count int
	for {
		if s.IssueOpts.MaxIssues > 0 && count >= s.IssueOpts.MaxIssues {
			break
		}

		var releases []*github.RepositoryRelease
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			releases, resp, err = client.Repositories.ListReleases(ctx, owner, repoName, opts)
			return err
		})
		if err != nil {
			return fmt.Errorf("list releases: %w", err)
		}

		for _, rel := range releases {
			if s.IssueOpts.MaxIssues > 0 && count >= s.IssueOpts.MaxIssues {
				break
			}
			createdAt := rel.GetCreatedAt().Time
			// Releases are returned newest-first; early-terminate if older than Since.
			if !s.IssueOpts.Since.IsZero() && createdAt.Before(s.IssueOpts.Since) {
				return nil
			}
			if !s.IssueOpts.Until.IsZero() && !createdAt.Before(s.IssueOpts.Until) {
				continue
			}
			if err := s.emitRelease(ctx, client, owner, repoName, rel, yield); err != nil {
				return err
			}
			count++
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	logger.Debug().Int("releases", count).Msg("releases scan complete")
	return nil
}

// emitRelease emits a release body fragment and scans its assets.
func (s *GitHub) emitRelease(ctx context.Context, client *github.Client, owner, repo string, rel *github.RepositoryRelease, yield FragmentsFunc) error {
	tag := rel.GetTagName()

	// Performance gate: check skip with release-level attrs before downloading
	// any assets. The yield wrapper is the authoritative filter (it has full
	// repo attrs), but checking here avoids unnecessary network I/O when a
	// release-tag or URL filter would discard everything anyway.
	if s.ShouldSkip != nil && s.ShouldSkip(map[string]string{
		AttrURL:              rel.GetHTMLURL(),
		AttrResource:         ResourceGitHubRelease,
		AttrGitHubReleaseTag: tag,
	}) {
		return nil
	}

	title := rel.GetName()
	body := rel.GetBody()
	if title != "" || body != "" {
		frag := Fragment{Raw: strings.TrimSpace(title + "\n" + body)}
		frag.SetAttr(AttrURL, rel.GetHTMLURL())
		frag.SetAttr(AttrResource, ResourceGitHubRelease)
		frag.SetAttr(AttrGitHubReleaseTag, tag)
		if err := yield(frag, nil); err != nil {
			return err
		}
	}
	if s.ScanReleaseAssets {
		if err := s.scanReleaseAssets(ctx, client, owner, repo, rel, yield); err != nil {
			logging.Warn().Err(err).Str("tag", tag).Msg("could not scan release assets")
		}
		if err := s.scanReleaseSourceArchives(ctx, rel, yield); err != nil {
			logging.Warn().Err(err).Str("tag", tag).Msg("could not scan release source archives")
		}
	}
	return nil
}

// scanSingleRelease scans one release identified by its tag.
func (s *GitHub) scanSingleRelease(ctx context.Context, client *github.Client, owner, repo, tag string, yield FragmentsFunc) error {
	var rel *github.RepositoryRelease
	err := s.withRetry(ctx, func() error {
		var err error
		rel, _, err = client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
		return err
	})
	if err != nil {
		return fmt.Errorf("get release %s: %w", tag, err)
	}
	return s.emitRelease(ctx, client, owner, repo, rel, yield)
}

// scanReleaseAssets lists and scans all downloadable assets for a release.
func (s *GitHub) scanReleaseAssets(ctx context.Context, client *github.Client, owner, repo string, rel *github.RepositoryRelease, yield FragmentsFunc) error {
	tag := rel.GetTagName()
	opts := &github.ListOptions{PerPage: 100}
	for {
		var assets []*github.ReleaseAsset
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			assets, resp, err = client.Repositories.ListReleaseAssets(ctx, owner, repo, rel.GetID(), opts)
			return err
		})
		if err != nil {
			return fmt.Errorf("list release assets for %s: %w", tag, err)
		}

		for _, asset := range assets {
			logger := logging.With().
				Str("tag", tag).
				Str("asset", asset.GetName()).Logger()
			logger.Debug().Msg("scanning release asset")
			if err := s.downloadAndScanReleaseAsset(ctx, client, owner, repo, rel, asset, yield); err != nil {
				logger.Error().Err(err).Msg("could not scan release asset")
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
}

// downloadAndScanReleaseAsset downloads a single release asset and scans it.
func (s *GitHub) downloadAndScanReleaseAsset(ctx context.Context, client *github.Client, owner, repo string, rel *github.RepositoryRelease, asset *github.ReleaseAsset, yield FragmentsFunc) error {
	start := time.Now()

	// Use an authenticated HTTP client so private-repo assets are accessible.
	var httpClient *http.Client
	if s.Token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: s.Token})
		httpClient = oauth2.NewClient(ctx, ts)
	}

	var rc io.ReadCloser
	err := s.withRetry(ctx, func() error {
		var err error
		rc, _, err = client.Repositories.DownloadReleaseAsset(ctx, owner, repo, asset.GetID(), httpClient)
		return err
	})
	if err != nil {
		return fmt.Errorf("download asset %s: %w", asset.GetName(), err)
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "betterleaks-release-asset-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		logging.Debug().Str("path", tmp.Name()).Msg("cleaning up release asset")
		os.Remove(tmp.Name())
	}()

	bytesWritten, err := io.Copy(tmp, rc)
	if err != nil {
		return fmt.Errorf("download asset %s: %w", asset.GetName(), err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	assetPath := fmt.Sprintf("releases/%s/%s", rel.GetTagName(), asset.GetName())
	assetAttrs := map[string]string{
		AttrGitHubReleaseTag:       rel.GetTagName(),
		AttrGitHubReleaseAssetName: asset.GetName(),
		AttrResource:               ResourceGitHubReleaseAsset,
	}

	file := &File{
		Content:         tmp,
		Path:            assetPath,
		MaxArchiveDepth: max(1, s.MaxArchiveDepth),
		ShouldSkip:      s.ShouldSkip,
	}

	err = file.Fragments(ctx, func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range assetAttrs {
				if k == AttrResource || fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
		}
		return yield(fragment, err)
	})
	logging.Debug().
		Str("tag", rel.GetTagName()).
		Str("asset", asset.GetName()).
		Int64("bytes", bytesWritten).
		Dur("asset_scan_ms", time.Since(start)).
		Msg("release asset scan complete")
	return err
}

// scanReleaseSourceArchives downloads and scans the auto-generated source code
// zip and tarball that GitHub attaches to every release.
func (s *GitHub) scanReleaseSourceArchives(ctx context.Context, rel *github.RepositoryRelease, yield FragmentsFunc) error {
	tag := rel.GetTagName()
	archives := []struct {
		rawURL   string
		filename string
	}{
		{rel.GetZipballURL(), "source-code.zip"},
		{rel.GetTarballURL(), "source-code.tar.gz"},
	}
	for _, a := range archives {
		if a.rawURL == "" {
			continue
		}
		logger := logging.With().Str("tag", tag).Str("archive", a.filename).Logger()
		logger.Debug().Msg("scanning release source archive")
		if err := s.downloadAndScanReleaseArchive(ctx, tag, a.rawURL, a.filename, yield); err != nil {
			logger.Error().Err(err).Msg("could not scan release source archive")
		}
	}
	return nil
}

// downloadAndScanReleaseArchive downloads an authenticated URL to a temp file and scans it.
// Used for the auto-generated source code zip/tarball on GitHub releases.
func (s *GitHub) downloadAndScanReleaseArchive(ctx context.Context, tag, rawURL, filename string, yield FragmentsFunc) error {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}

	// Follow redirects with auth preserved.
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if s.Token != "" {
				req.Header.Set("Authorization", "Bearer "+s.Token)
			}
			return nil
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}

	tmp, err := os.CreateTemp("", "betterleaks-release-src-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		logging.Debug().Str("path", tmp.Name()).Msg("cleaning up release source archive")
		os.Remove(tmp.Name())
	}()

	bytesWritten, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	archivePath := fmt.Sprintf("releases/%s/%s", tag, filename)
	archiveAttrs := map[string]string{
		AttrGitHubReleaseTag:       tag,
		AttrGitHubReleaseAssetName: filename,
		AttrResource:               ResourceGitHubReleaseAsset,
	}

	file := &File{
		Content:         tmp,
		Path:            archivePath,
		MaxArchiveDepth: max(1, s.MaxArchiveDepth),
		ShouldSkip:      s.ShouldSkip,
	}

	err = file.Fragments(ctx, func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range archiveAttrs {
				if k == AttrResource || fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
		}
		return yield(fragment, err)
	})
	logging.Debug().
		Str("tag", tag).
		Str("archive", filename).
		Int64("bytes", bytesWritten).
		Dur("archive_scan_ms", time.Since(start)).
		Msg("release source archive scan complete")
	return err
}

// ============ Gists scan path ============

// scanUserGists scans all public gists for a GitHub user via the REST API.
func (s *GitHub) scanUserGists(ctx context.Context, client *github.Client, user string, yield FragmentsFunc) error {
	logger := logging.With().Str("user", user).Logger()
	logger.Info().Msg("scanning gists")

	opts := &github.GistListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	if !s.IssueOpts.Since.IsZero() {
		opts.Since = s.IssueOpts.Since
	}

	var count int
	for {
		var gists []*github.Gist
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			gists, resp, err = client.Gists.List(ctx, user, opts)
			return err
		})
		if err != nil {
			return fmt.Errorf("list gists for %s: %w", user, err)
		}

		for _, gist := range gists {
			updatedAt := gist.GetUpdatedAt().Time
			if !s.IssueOpts.Until.IsZero() && !updatedAt.Before(s.IssueOpts.Until) {
				continue
			}
			if err := s.emitGist(ctx, client, gist.GetID(), gist.GetOwner().GetLogin(), gist.GetHTMLURL(), &count, yield); err != nil {
				logger.Error().Err(err).Str("gist_id", gist.GetID()).Msg("could not scan gist")
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	logger.Debug().Int("gists", count).Msg("gists scan complete")
	return nil
}

// emitGist fetches a single gist by ID and emits one fragment per file.
func (s *GitHub) emitGist(ctx context.Context, client *github.Client, gistID, owner, htmlURL string, count *int, yield FragmentsFunc) error {
	var full *github.Gist
	err := s.withRetry(ctx, func() error {
		var err error
		full, _, err = client.Gists.Get(ctx, gistID)
		return err
	})
	if err != nil {
		return fmt.Errorf("get gist %s: %w", gistID, err)
	}

	for filename, file := range full.Files {
		content := file.GetContent()
		if content == "" {
			continue
		}
		frag := Fragment{Raw: content}
		frag.SetAttr(AttrURL, htmlURL)
		frag.SetAttr(AttrResource, ResourceGitHubGist)
		frag.SetAttr(AttrGitHubGistID, gistID)
		frag.SetAttr(AttrGitHubGistOwner, owner)
		frag.SetAttr(AttrGitHubGistFilename, string(filename))
		if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
			if err := yield(frag, nil); err != nil {
				return err
			}
		}
		(*count)++
	}
	return nil
}

// ============ Discussions scan path ============

// GraphQL types for discussions.

type ghDiscussionCommentReply struct {
	DatabaseId int64
	Body       string
	Url        string
	CreatedAt  time.Time
	Author     ghActor
}

type ghDiscussionComment struct {
	DatabaseId int64
	Body       string
	Url        string
	CreatedAt  time.Time
	Author     ghActor
	Replies    struct {
		Nodes    []ghDiscussionCommentReply
		PageInfo ghPageInfo
	} `graphql:"replies(first: $repliesFirst)"`
}

type ghDiscussionCommentConnection struct {
	Nodes    []ghDiscussionComment
	PageInfo ghPageInfo
}

type ghDiscussionNode struct {
	Number    int
	Title     string
	Body      string
	Url       string
	Author    ghActor
	CreatedAt time.Time
	Comments  ghDiscussionCommentConnection `graphql:"comments(first: $commentsFirst)"`
}

type ghRepoDiscussionsQuery struct {
	Repository struct {
		Discussions struct {
			Nodes    []ghDiscussionNode
			PageInfo ghPageInfo
		} `graphql:"discussions(first: $discussionsFirst, after: $discussionsAfter, orderBy: {field: CREATED_AT, direction: DESC})"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

type ghDiscussionCommentsTailQuery struct {
	Repository struct {
		Discussion struct {
			Comments ghDiscussionCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"discussion(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

type ghDiscussionReplyTailQuery struct {
	Node struct {
		Comment struct {
			Replies struct {
				Nodes    []ghDiscussionCommentReply
				PageInfo ghPageInfo
			} `graphql:"replies(first: $repliesFirst, after: $repliesAfter)"`
		} `graphql:"... on DiscussionComment"`
	} `graphql:"node(id: $commentId)"`
	RateLimit ghRateLimit
}

// scanDiscussions scans GitHub Discussions for a repo via the GraphQL API.
func (s *GitHub) scanDiscussions(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	name := repo.GetName()
	logger := logging.With().Str("repo", repo.GetFullName()).Logger()
	logger.Info().Msg("scanning discussions")
	start := time.Now()

	var after *githubv4.String
	var count int
	var commentCount int

	for {
		if s.IssueOpts.MaxIssues > 0 && count >= s.IssueOpts.MaxIssues {
			break
		}

		vars := map[string]any{
			"owner":            githubv4.String(owner),
			"repo":             githubv4.String(name),
			"discussionsFirst": githubv4.Int(50),
			"discussionsAfter": after,
			"commentsFirst":    githubv4.Int(50),
			"repliesFirst":     githubv4.Int(50),
		}

		var q ghRepoDiscussionsQuery
		if err := s.gqlQuery(ctx, &q, vars, &q.RateLimit); err != nil {
			return fmt.Errorf("graphql discussions: %w", err)
		}

		for _, d := range q.Repository.Discussions.Nodes {
			if s.IssueOpts.MaxIssues > 0 && count >= s.IssueOpts.MaxIssues {
				break
			}
			// Results are ordered CREATED_AT DESC; early-terminate on Since.
			if !s.IssueOpts.Since.IsZero() && d.CreatedAt.Before(s.IssueOpts.Since) {
				return nil
			}
			if !s.IssueOpts.Until.IsZero() && !d.CreatedAt.Before(s.IssueOpts.Until) {
				continue
			}
			if err := s.emitDiscussion(ctx, owner, name, d, &commentCount, yield); err != nil {
				return err
			}
			count++
		}

		if !q.Repository.Discussions.PageInfo.HasNextPage {
			break
		}
		after = githubv4.NewString(q.Repository.Discussions.PageInfo.EndCursor)
	}

	logger.Debug().
		Int("discussions", count).
		Int("comments", commentCount).
		Dur("discussions_ms", time.Since(start)).
		Msg("discussions scan complete")
	return nil
}

// emitDiscussion emits a discussion and all its comments/replies.
func (s *GitHub) emitDiscussion(ctx context.Context, owner, name string, d ghDiscussionNode, totalComments *int, yield FragmentsFunc) error {
	numStr := strconv.Itoa(d.Number)

	if d.Title != "" || d.Body != "" {
		frag := Fragment{Raw: strings.TrimSpace(d.Title + "\n" + d.Body)}
		frag.SetAttr(AttrURL, d.Url)
		frag.SetAttr(AttrResource, ResourceGitHubDiscussion)
		frag.SetAttr(AttrGitHubDiscussionNumber, numStr)
		if err := yield(frag, nil); err != nil {
			return err
		}
	}

	if !s.ScanComments {
		return nil
	}

	var itemComments int
	if err := s.emitDiscussionComments(ctx, d.Url, numStr, d.Comments.Nodes, &itemComments, yield); err != nil {
		return err
	}

	// Tail-paginate comments if needed.
	cursor := d.Comments.PageInfo.EndCursor
	hasMore := d.Comments.PageInfo.HasNextPage
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && itemComments >= s.IssueOpts.MaxComments {
			break
		}
		var tail ghDiscussionCommentsTailQuery
		vars := map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"number":        githubv4.Int(d.Number),
			"commentsFirst": githubv4.Int(50),
			"commentsAfter": githubv4.NewString(cursor),
			"repliesFirst":  githubv4.Int(50),
		}
		if err := s.gqlQuery(ctx, &tail, vars, &tail.RateLimit); err != nil {
			return fmt.Errorf("discussion %d comments tail: %w", d.Number, err)
		}
		if err := s.emitDiscussionComments(ctx, d.Url, numStr, tail.Repository.Discussion.Comments.Nodes, &itemComments, yield); err != nil {
			return err
		}
		hasMore = tail.Repository.Discussion.Comments.PageInfo.HasNextPage
		cursor = tail.Repository.Discussion.Comments.PageInfo.EndCursor
	}

	*totalComments += itemComments
	return nil
}

// emitDiscussionComments emits comments and their replies for a discussion.
func (s *GitHub) emitDiscussionComments(ctx context.Context, discussionURL, discussionNum string, comments []ghDiscussionComment, count *int, yield FragmentsFunc) error {
	for _, c := range comments {
		if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
			return nil
		}
		if !s.IssueOpts.Since.IsZero() && c.CreatedAt.Before(s.IssueOpts.Since) {
			continue
		}
		if !s.IssueOpts.Until.IsZero() && !c.CreatedAt.Before(s.IssueOpts.Until) {
			continue
		}
		if c.Body != "" {
			frag := Fragment{Raw: c.Body}
			u := c.Url
			if u == "" {
				u = discussionURL
			}
			frag.SetAttr(AttrURL, u)
			frag.SetAttr(AttrResource, ResourceGitHubComment)
			frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(c.DatabaseId, 10))
			frag.SetAttr(AttrGitHubDiscussionNumber, discussionNum)
			if err := yield(frag, nil); err != nil {
				return err
			}
			(*count)++
		}

		// Emit inline replies.
		for _, r := range c.Replies.Nodes {
			if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
				return nil
			}
			if r.Body == "" {
				continue
			}
			if !s.IssueOpts.Since.IsZero() && r.CreatedAt.Before(s.IssueOpts.Since) {
				continue
			}
			if !s.IssueOpts.Until.IsZero() && !r.CreatedAt.Before(s.IssueOpts.Until) {
				continue
			}
			frag := Fragment{Raw: r.Body}
			u := r.Url
			if u == "" {
				u = discussionURL
			}
			frag.SetAttr(AttrURL, u)
			frag.SetAttr(AttrResource, ResourceGitHubComment)
			frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(r.DatabaseId, 10))
			frag.SetAttr(AttrGitHubDiscussionNumber, discussionNum)
			if err := yield(frag, nil); err != nil {
				return err
			}
			(*count)++
		}

		// Tail-paginate this comment's replies if there are more.
		if c.Replies.PageInfo.HasNextPage {
			if err := s.tailDiscussionReplies(ctx, discussionURL, discussionNum, githubv4.ID(strconv.FormatInt(c.DatabaseId, 10)), c.Replies.PageInfo.EndCursor, count, yield); err != nil {
				return err
			}
		}
	}
	return nil
}

// tailDiscussionReplies paginates additional replies for a discussion comment node.
func (s *GitHub) tailDiscussionReplies(ctx context.Context, discussionURL, discussionNum string, commentId githubv4.ID, cursor githubv4.String, count *int, yield FragmentsFunc) error {
	hasMore := true
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
			return nil
		}
		var tail ghDiscussionReplyTailQuery
		vars := map[string]any{
			"commentId":    commentId,
			"repliesFirst": githubv4.Int(50),
			"repliesAfter": githubv4.NewString(cursor),
		}
		if err := s.gqlQuery(ctx, &tail, vars, &tail.RateLimit); err != nil {
			return fmt.Errorf("discussion comment replies tail: %w", err)
		}
		for _, r := range tail.Node.Comment.Replies.Nodes {
			if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
				return nil
			}
			if r.Body == "" {
				continue
			}
			frag := Fragment{Raw: r.Body}
			u := r.Url
			if u == "" {
				u = discussionURL
			}
			frag.SetAttr(AttrURL, u)
			frag.SetAttr(AttrResource, ResourceGitHubComment)
			frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(r.DatabaseId, 10))
			frag.SetAttr(AttrGitHubDiscussionNumber, discussionNum)
			if err := yield(frag, nil); err != nil {
				return err
			}
			(*count)++
		}
		hasMore = tail.Node.Comment.Replies.PageInfo.HasNextPage
		cursor = tail.Node.Comment.Replies.PageInfo.EndCursor
	}
	return nil
}

// ============ Single-resource (--url) scan path ============

// parsedGitHubURL holds the components extracted from a GitHub resource URL.
type parsedGitHubURL struct {
	Owner    string // repo owner or gist user
	Repo     string // repo name (empty for gists)
	Resource string // "issue", "pr", "actions_run", "release", "discussion", "gist"
	ID       string // number, run ID, tag name, or gist ID
	Host     string // host (for GHE detection)
}

// parseGitHubURL parses a GitHub resource URL into its components.
// Supports github.com and GitHub Enterprise URLs.
func parseGitHubURL(rawURL string) (*parsedGitHubURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}

	host := strings.ToLower(u.Hostname())

	// Gist: gist.github.com/{user}/{id} or gist.{ghe-host}/{user}/{id}
	if strings.HasPrefix(host, "gist.") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("gist URL must be gist.github.com/{user}/{id}")
		}
		return &parsedGitHubURL{Owner: parts[0], Resource: "gist", ID: parts[1], Host: host}, nil
	}

	// All other resources: {host}/{owner}/{repo}/{type}/...
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 4 {
		return nil, fmt.Errorf("URL must point to a specific GitHub resource (issue, PR, discussion, release, or action run)")
	}
	owner, repo := parts[0], parts[1]
	kind, id := parts[2], parts[3]

	p := &parsedGitHubURL{Owner: owner, Repo: repo, Host: host}

	switch kind {
	case "issues":
		p.Resource = "issue"
		p.ID = id
	case "pull":
		p.Resource = "pr"
		p.ID = id
	case "discussions":
		p.Resource = "discussion"
		p.ID = id
	case "releases":
		// releases/tag/{tag}
		if id != "tag" || len(parts) < 5 || parts[4] == "" {
			return nil, fmt.Errorf("release URL must be .../releases/tag/{tag}")
		}
		p.Resource = "release"
		p.ID = parts[4]
	case "actions":
		// actions/runs/{id}
		if id != "runs" || len(parts) < 5 || parts[4] == "" {
			return nil, fmt.Errorf("actions URL must be .../actions/runs/{id}")
		}
		p.Resource = "actions_run"
		p.ID = parts[4]
	default:
		return nil, fmt.Errorf("unsupported GitHub URL type %q; supported: issues, pull, discussions, releases/tag, actions/runs, gist", kind)
	}

	return p, nil
}

// scanURL dispatches to the appropriate single-resource scanner based on the URL.
func (s *GitHub) scanURL(ctx context.Context, client *github.Client, yield FragmentsFunc) error {
	// URL mode scans a single explicit resource in full. Force all content
	// flags on regardless of what the caller passed — the user asked for this
	// specific thing, so emit everything it contains.
	// This is safe because URL mode short-circuits before any other scan runs.
	s.ScanIssues = true
	s.ScanPRs = true
	s.ScanComments = true
	s.ScanDiscussions = true
	s.ScanReleases = true
	s.ScanReleaseAssets = true

	parsed, err := parseGitHubURL(s.URL)
	if err != nil {
		return fmt.Errorf("--url: %w", err)
	}

	// For repo-level resources, fetch repo metadata and stamp it on all fragments.
	if parsed.Resource != "gist" {
		repo, err := s.fetchRepo(ctx, client, parsed.Owner, parsed.Repo)
		if err != nil {
			return fmt.Errorf("fetch repo %s/%s: %w", parsed.Owner, parsed.Repo, err)
		}
		repoAttrs := s.repoAttributes(repo, "")
		var yieldMu sync.Mutex
		origYield := yield
		yield = func(fragment Fragment, err error) error {
			if err == nil {
				for k, v := range repoAttrs {
					if v == "" || fragment.Attr(k) != "" {
						continue
					}
					fragment.SetAttr(k, v)
				}
				if s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
					return nil
				}
			}
			yieldMu.Lock()
			defer yieldMu.Unlock()
			return origYield(fragment, err)
		}
	}

	switch parsed.Resource {
	case "issue":
		num, err := strconv.Atoi(parsed.ID)
		if err != nil {
			return fmt.Errorf("invalid issue number %q", parsed.ID)
		}
		return s.scanSingleIssue(ctx, parsed.Owner, parsed.Repo, num, yield)
	case "pr":
		num, err := strconv.Atoi(parsed.ID)
		if err != nil {
			return fmt.Errorf("invalid PR number %q", parsed.ID)
		}
		return s.scanSinglePR(ctx, parsed.Owner, parsed.Repo, num, yield)
	case "discussion":
		num, err := strconv.Atoi(parsed.ID)
		if err != nil {
			return fmt.Errorf("invalid discussion number %q", parsed.ID)
		}
		return s.scanSingleDiscussion(ctx, parsed.Owner, parsed.Repo, num, yield)
	case "release":
		return s.scanSingleRelease(ctx, client, parsed.Owner, parsed.Repo, parsed.ID, yield)
	case "actions_run":
		runID, err := strconv.ParseInt(parsed.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid run ID %q", parsed.ID)
		}
		return s.scanSingleActionRun(ctx, client, parsed.Owner, parsed.Repo, runID, yield)
	case "gist":
		return s.emitGist(ctx, client, parsed.ID, parsed.Owner, s.URL, nil, yield)
	}
	return nil
}

// GraphQL query types for single-resource lookups.

type ghSingleIssueQuery struct {
	Repository struct {
		Issue ghIssueNode `graphql:"issue(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

type ghSinglePRQuery struct {
	Repository struct {
		PullRequest ghPRNode `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

type ghSingleDiscussionQuery struct {
	Repository struct {
		Discussion ghDiscussionNode `graphql:"discussion(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
	RateLimit ghRateLimit
}

func (s *GitHub) scanSingleIssue(ctx context.Context, owner, repo string, number int, yield FragmentsFunc) error {
	var q ghSingleIssueQuery
	vars := map[string]any{
		"owner":         githubv4.String(owner),
		"repo":          githubv4.String(repo),
		"number":        githubv4.Int(number),
		"commentsFirst": githubv4.Int(50),
	}
	if err := s.gqlQuery(ctx, &q, vars, &q.RateLimit); err != nil {
		return fmt.Errorf("fetch issue %d: %w", number, err)
	}
	var dummy int
	return s.emitIssueAndComments(ctx, owner, repo, q.Repository.Issue, &dummy, yield)
}

func (s *GitHub) scanSinglePR(ctx context.Context, owner, repo string, number int, yield FragmentsFunc) error {
	var q ghSinglePRQuery
	vars := map[string]any{
		"owner":         githubv4.String(owner),
		"repo":          githubv4.String(repo),
		"number":        githubv4.Int(number),
		"commentsFirst": githubv4.Int(50),
		"threadsFirst":  githubv4.Int(50),
	}
	if err := s.gqlQuery(ctx, &q, vars, &q.RateLimit); err != nil {
		return fmt.Errorf("fetch pr %d: %w", number, err)
	}
	var dummy int
	return s.emitPRAndComments(ctx, owner, repo, q.Repository.PullRequest, &dummy, yield)
}

func (s *GitHub) scanSingleDiscussion(ctx context.Context, owner, repo string, number int, yield FragmentsFunc) error {
	var q ghSingleDiscussionQuery
	vars := map[string]any{
		"owner":         githubv4.String(owner),
		"repo":          githubv4.String(repo),
		"number":        githubv4.Int(number),
		"commentsFirst": githubv4.Int(50),
		"repliesFirst":  githubv4.Int(50),
	}
	if err := s.gqlQuery(ctx, &q, vars, &q.RateLimit); err != nil {
		return fmt.Errorf("fetch discussion %d: %w", number, err)
	}
	var dummy int
	return s.emitDiscussion(ctx, owner, repo, q.Repository.Discussion, &dummy, yield)
}

// scanSingleActionRun scans logs (and optionally artifacts) for one workflow run.
func (s *GitHub) scanSingleActionRun(ctx context.Context, client *github.Client, owner, repo string, runID int64, yield FragmentsFunc) error {
	var run *github.WorkflowRun
	err := s.withRetry(ctx, func() error {
		var err error
		run, _, err = client.Actions.GetWorkflowRunByID(ctx, owner, repo, runID)
		return err
	})
	if err != nil {
		return fmt.Errorf("get action run %d: %w", runID, err)
	}
	if err := s.scanRunLogs(ctx, client, owner, repo, run, yield); err != nil {
		if !isGitHubGone(err) {
			return err
		}
	}
	if s.Actions.ScanArtifacts {
		return s.scanRunArtifacts(ctx, client, owner, repo, run, yield)
	}
	return nil
}
