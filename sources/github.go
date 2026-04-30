package sources

import (
	"context"
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
	MaxIssues   int // max issues/PRs to fetch per repo (0 = no limit)
	MaxComments int // max comments to fetch per issue or PR (0 = no limit)
}

// Fragments enumerates GitHub repos and scans each one.
func (s *GitHub) Fragments(ctx context.Context, yield FragmentsFunc) error {
	start := time.Now()
	client := s.newClient(ctx)
	s.gqlClient = s.newGraphQLClient(ctx)
	s.apiCalls.Store(0)
	s.gqlRemaining.Store(-1)
	s.gqlResetAt.Store(0)

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
		} else {
			logger.Debug().Dur("git_ms", time.Since(gitStart)).Msg("git scan complete")
		}
		return nil
	})

	if s.ScanActions {
		g.Go(func() error {
			actionsStart := time.Now()
			if err := s.scanActions(gctx, client, repo, ghYield); err != nil {
				logger.Error().Err(err).Msg("actions scan failed")
			} else {
				logger.Debug().Dur("actions_ms", time.Since(actionsStart)).Msg("actions scan complete")
			}
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
			} else {
				logger.Debug().Dur("issues_prs_ms", time.Since(issuesStart)).Msg("issues/prs scan complete")
			}
			return nil
		})
	}

	_ = g.Wait()
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

// cloneRepo performs a bare git clone with token auth injected into the URL.
// Uses a broad refspec (+refs/*:refs/remotes/origin/*) to fetch all refs
// including PR heads, tags, and non-standard refs so that git log --all
// can traverse the complete commit graph.
func (s *GitHub) cloneRepo(ctx context.Context, repo *github.Repository, dest string) error {
	cloneURL := repo.GetCloneURL()
	if s.Token != "" {
		u, err := url.Parse(cloneURL)
		if err == nil {
			u.User = url.UserPassword("x-access-token", s.Token)
			cloneURL = u.String()
		}
	}
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--bare", "--quiet",
		"-c", "remote.origin.fetch=+refs/*:refs/remotes/origin/*",
		cloneURL, dest,
	)
	cmd.Env = gitConfigIsolationEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone: %w: %s", err, output)
	}
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
	if len(s.Actions.Workflows) > 0 {
		var all []*github.WorkflowRun
		for _, wf := range s.Actions.Workflows {
			runs, err := s.paginateWorkflowRuns(ctx, client, owner, repo, wf, opts, maxRuns-len(all))
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
		} `graphql:"issues(first: $issuesFirst, after: $issuesAfter)"`
		PullRequests struct {
			Nodes    []ghPRNode
			PageInfo ghPageInfo
		} `graphql:"pullRequests(first: $prsFirst, after: $prsAfter)"`
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

// gqlQuery wraps every GraphQL call with rate-limit handling and transient-error retries.
func (s *GitHub) gqlQuery(ctx context.Context, q any, vars map[string]any, rl *ghRateLimit) error {
	const maxAttempts = 4
	for attempt := range maxAttempts {
		if err := ghAwaitRateLimit(ctx); err != nil {
			return err
		}

		err := s.gqlClient.Query(ctx, q, vars)
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

		msg := err.Error()
		if strings.Contains(msg, "rate limit") || strings.Contains(msg, "secondary rate limit") {
			ghSetRateLimitPause(60 * time.Second)
			continue
		}
		// Transient network errors get one bounded retry with exponential backoff.
		if attempt < maxAttempts-1 && (strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset")) {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
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
		if !issuesDone {
			for _, issue := range q.Repository.Issues.Nodes {
				if s.IssueOpts.MaxIssues > 0 && issueCount+prCount >= s.IssueOpts.MaxIssues {
					break
				}
				if err := s.emitIssueAndComments(ctx, owner, name, issue, &commentCount, yield); err != nil {
					return err
				}
				issueCount++
			}
			if !q.Repository.Issues.PageInfo.HasNextPage {
				issuesDone = true
			} else {
				issuesAfter = githubv4.NewString(q.Repository.Issues.PageInfo.EndCursor)
			}
		}

		// Process PRs from this page.
		if !prsDone {
			for _, pr := range q.Repository.PullRequests.Nodes {
				if s.IssueOpts.MaxIssues > 0 && issueCount+prCount >= s.IssueOpts.MaxIssues {
					break
				}
				if err := s.emitPRAndComments(ctx, owner, name, pr, &commentCount, yield); err != nil {
					return err
				}
				prCount++
			}
			if !q.Repository.PullRequests.PageInfo.HasNextPage {
				prsDone = true
			} else {
				prsAfter = githubv4.NewString(q.Repository.PullRequests.PageInfo.EndCursor)
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

func (s *GitHub) emitIssueAndComments(ctx context.Context, owner, name string, issue ghIssueNode, commentCount *int, yield FragmentsFunc) error {
	if s.ScanIssues && (issue.Title != "" || issue.Body != "") {
		frag := Fragment{Raw: strings.TrimSpace(issue.Title + "\n\n" + issue.Body)}
		frag.SetAttr(AttrPath, issue.Url)
		frag.SetAttr(AttrResource, ResourceGitHubIssue)
		frag.SetAttr(AttrGitHubIssueNumber, strconv.Itoa(issue.Number))
		if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
			if err := yield(frag, nil); err != nil {
				return err
			}
		}
	}

	if !s.ScanComments {
		return nil
	}

	// First page of comments (already in hand).
	if err := s.emitCommentNodes(issue.Comments.Nodes, issue.Url, "", strconv.Itoa(issue.Number), commentCount, yield); err != nil {
		return err
	}

	// Tail pages.
	cursor := issue.Comments.PageInfo.EndCursor
	hasMore := issue.Comments.PageInfo.HasNextPage
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && *commentCount >= s.IssueOpts.MaxComments {
			return nil
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
		if err := s.emitCommentNodes(tail.Repository.Issue.Comments.Nodes, issue.Url, "", strconv.Itoa(issue.Number), commentCount, yield); err != nil {
			return err
		}
		hasMore = tail.Repository.Issue.Comments.PageInfo.HasNextPage
		cursor = tail.Repository.Issue.Comments.PageInfo.EndCursor
	}
	return nil
}

func (s *GitHub) emitPRAndComments(ctx context.Context, owner, name string, pr ghPRNode, commentCount *int, yield FragmentsFunc) error {
	if s.ScanPRs && (pr.Title != "" || pr.Body != "") {
		frag := Fragment{Raw: strings.TrimSpace(pr.Title + "\n\n" + pr.Body)}
		frag.SetAttr(AttrPath, pr.Url)
		frag.SetAttr(AttrResource, ResourceGitHubPR)
		frag.SetAttr(AttrGitHubPRNumber, strconv.Itoa(pr.Number))
		if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
			if err := yield(frag, nil); err != nil {
				return err
			}
		}
	}

	if !s.ScanComments {
		return nil
	}

	prNumStr := strconv.Itoa(pr.Number)

	// Issue-style PR comments: first page in hand, then tail.
	if err := s.emitCommentNodes(pr.Comments.Nodes, pr.Url, prNumStr, "", commentCount, yield); err != nil {
		return err
	}
	cursor := pr.Comments.PageInfo.EndCursor
	hasMore := pr.Comments.PageInfo.HasNextPage
	for hasMore {
		if s.IssueOpts.MaxComments > 0 && *commentCount >= s.IssueOpts.MaxComments {
			return nil
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
		if err := s.emitCommentNodes(tail.Repository.PullRequest.Comments.Nodes, pr.Url, prNumStr, "", commentCount, yield); err != nil {
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
			if err := s.emitCommentNodes(thread.Comments.Nodes, pr.Url, prNumStr, "", commentCount, yield); err != nil {
				return err
			}
			// Tail-paginate this thread's comments if needed.
			if thread.Comments.PageInfo.HasNextPage {
				if err := s.tailThreadComments(ctx, pr.Url, prNumStr, thread.Id, thread.Comments.PageInfo.EndCursor, commentCount, yield); err != nil {
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
		*count++

		frag := Fragment{Raw: c.Body}
		u := c.Url
		if u == "" {
			u = parentURL
		}
		frag.SetAttr(AttrPath, u)
		frag.SetAttr(AttrResource, ResourceGitHubComment)
		frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(c.DatabaseId, 10))
		if prNum != "" {
			frag.SetAttr(AttrGitHubPRNumber, prNum)
		}
		if issueNum != "" {
			frag.SetAttr(AttrGitHubIssueNumber, issueNum)
		}
		if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
			if err := yield(frag, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
