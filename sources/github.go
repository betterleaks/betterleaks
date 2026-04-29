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
	"time"

	"github.com/fatih/semgroup"
	"github.com/google/go-github/v72/github"
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
	Workers         int    // git workers per repo (0 = single process)
	LogOpts         string

	// GitHub API
	BaseURL string // GitHub Enterprise base URL; empty = github.com

	// Actions scanning
	ScanActions bool
	Actions     ActionsOptions
}

// ActionsOptions controls which workflow runs and artifacts to scan.
type ActionsOptions struct {
	Workflows     []string      // filter to specific workflow file names
	MaxAge        time.Duration // only scan runs newer than this
	MaxRuns       int           // max runs to fetch per repo (0 = 50)
	ScanArtifacts bool          // also download and scan artifacts
}

// Fragments enumerates GitHub repos and scans each one.
func (s *GitHub) Fragments(ctx context.Context, yield FragmentsFunc) error {
	client := s.newClient(ctx)

	repos, err := s.enumerateRepos(ctx, client)
	if err != nil {
		return fmt.Errorf("enumerate repos: %w", err)
	}

	logging.Info().Int("repos", len(repos)).Msg("GitHub repos to scan")

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, runtime.NumCPU()/2))

	for _, repo := range repos {
		g.Go(func() error {
			return s.scanRepo(gctx, client, repo, yield)
		})
	}
	return g.Wait()
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
// If actions scanning is enabled, it also scans workflow run logs and artifacts.
func (s *GitHub) scanRepo(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	name := repo.GetFullName()
	logger := logging.With().Str("repo", name).Logger()
	logger.Info().Msg("scanning repo")

	// Wrap yield to stamp GitHub metadata on every fragment from this repo.
	ghYield := func(fragment Fragment, err error) error {
		if err == nil {
			fragment.SetAttr(AttrGitHubOrg, repo.GetOwner().GetLogin())
			fragment.SetAttr(AttrGitHubRepo, name)
			fragment.SetAttr(AttrGitHubRepoURL, repo.GetHTMLURL())
			fragment.SetAttr(AttrGitHubVisibility, repo.GetVisibility())
			if chain := fragment.Attr(AttrSourceChain); chain != "" {
				fragment.SetAttr(AttrSourceChain, "github > "+chain)
			} else {
				fragment.SetAttr(AttrSourceChain, "github")
			}
		}
		return yield(fragment, err)
	}

	if err := s.scanRepoGit(ctx, repo, ghYield); err != nil {
		logger.Error().Err(err).Msg("git scan failed")
	}

	if s.ScanActions {
		if err := s.scanActions(ctx, client, repo, ghYield); err != nil {
			logger.Error().Err(err).Msg("actions scan failed")
		}
	}

	return nil
}

// scanRepoGit clones and scans a repo's git history.
func (s *GitHub) scanRepoGit(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	name := repo.GetFullName()
	logger := logging.With().Str("repo", name).Logger()

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
	logger.Debug().Msg("clone complete")

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

	logger.Debug().Msg("starting git scan")
	scanErr := src.Fragments(ctx, yield)
	logger.Debug().Msg("git scan complete")
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
		opts.Page = resp.NextPage
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
		opts.Page = resp.NextPage
	}
	return all, nil
}

// withRetry retries an API call up to 3 times on rate limit errors.
func (s *GitHub) withRetry(ctx context.Context, fn func() error) error {
	const maxRetries = 3
	for attempt := range maxRetries {
		err := fn()
		if err == nil {
			return nil
		}

		var rateLimitErr *github.RateLimitError
		if errors.As(err, &rateLimitErr) && attempt < maxRetries-1 {
			wait := time.Until(rateLimitErr.Rate.Reset.Time) + time.Second
			if wait < 0 {
				wait = time.Second
			}
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

// isExcluded checks if a repo full name matches any exclusion glob.
func (s *GitHub) isExcluded(fullName string) bool {
	for _, pattern := range s.ExcludeRepos {
		if matched, _ := filepath.Match(pattern, fullName); matched {
			return true
		}
	}
	return false
}

// scanActions scans workflow run logs (and optionally artifacts) for a repo.
func (s *GitHub) scanActions(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	logger := logging.With().Str("repo", repo.GetFullName()).Logger()
	logger.Info().Msg("scanning actions")

	runs, err := s.listWorkflowRuns(ctx, client, owner, repoName)
	if err != nil {
		return fmt.Errorf("list workflow runs: %w", err)
	}
	logger.Debug().Int("runs", len(runs)).Msg("workflow runs to scan")

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

	logger.Debug().Msg("actions scan complete")
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

	if _, err := io.Copy(tmp, resp.Body); err != nil {
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
		AttrSourceChain:          "actions",
	}

	file := &File{
		Content:         tmp,
		Path:            zipPath,
		MaxArchiveDepth: max(1, s.MaxArchiveDepth), // must be >= 1 to extract the zip
		ShouldSkip:      s.ShouldSkip,
	}

	return file.Fragments(ctx, func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range actionsAttrs {
				if fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
		}
		return yield(fragment, err)
	})
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

// splitRepoSlug splits "owner/repo" into owner and repo.
func splitRepoSlug(slug string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("expected owner/repo format, got %q", slug)
	}
	return owner, repo, nil
}
