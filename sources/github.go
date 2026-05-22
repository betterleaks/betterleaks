package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/semgroup"
	"github.com/google/go-github/v72/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/internal/httpclient"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

const (
	// Retry/concurrency limits.
	defaultActionsWorkers = 4
	itemsPerPage          = 100
	gqlIssuesFirst        = 50
	gqlPRsFirst           = 25
	gqlCommentsFirst      = 25
	gqlThreadsFirst       = 20
	gqlRepliesFirst       = 25
	gqlCommentsTailFirst  = 50
	gqlRepliesTailFirst   = 50
	gqlThreadsTailFirst   = 50
)

// GitHub enumerates repositories via the GitHub API and delegates scanning
// to the Git source for each cloned repo.
type GitHub struct {
	// Auth
	Token string

	// Filtering
	ExcludeRepos []string // glob patterns matched against "owner/repo"

	// Include and Exclude specify resource types by name (e.g. "repos", "prs").
	// Validate applies these when Resources is empty.
	Include []string
	Exclude []string

	// Resources controls which resource types to scan.
	// Populated automatically by Validate from Include/Exclude when empty,
	// or set directly by callers who want programmatic control.
	Resources GitHubResourceSet

	// Scan config (passed through to Git/ParallelGit per repo)
	ShouldSkip      SkipFunc
	Sema            *semgroup.Group
	MaxArchiveDepth int
	Workers         int // git workers per repo (0 = single process)
	LogOpts         string

	// GitHub API
	BaseURL       string // GitHub Enterprise base URL; empty = github.com
	Actions       ActionsOptions
	DateRangeOpts DateRangeOptions

	// Target URL (required).
	URL string

	// Internal REST client and retry transport (initialized in Fragments).
	restRetry *httpclient.RetryTransport

	// Internal GraphQL client (initialized in Fragments).
	gqlClient    *githubv4.Client
	gqlRetry     *httpclient.RetryTransport
	gqlSem       chan struct{} // limits concurrent GraphQL round-trips
	gqlRemaining atomic.Int64  // latest X-RateLimit-Remaining from gqlRetry
	gqlResetAt   atomic.Int64  // latest X-RateLimit-Reset epoch from gqlRetry
}

// ActionsOptions controls which workflow runs and artifacts to scan.
type ActionsOptions struct {
	Workflows []string // filter to specific workflow file names
}

// DateRangeOptions controls date-range filtering across API-backed GitHub resources.
type DateRangeOptions struct {
	Since time.Time // only scan items created on or after this time (zero = no lower bound)
	Until time.Time // only scan items created before this time (zero = no upper bound)
}

// GitHubResourceType identifies a scannable GitHub resource category.
type GitHubResourceType string

const (
	GitHubResourceTypeRepos           GitHubResourceType = "repos"
	GitHubResourceTypeForks           GitHubResourceType = "forks"
	GitHubResourceTypePRs             GitHubResourceType = "prs"
	GitHubResourceTypePRComments      GitHubResourceType = "pr-comments"
	GitHubResourceTypeIssues          GitHubResourceType = "issues"
	GitHubResourceTypeIssueComments   GitHubResourceType = "issue-comments"
	GitHubResourceTypeActions         GitHubResourceType = "actions"
	GitHubResourceTypeActionArtifacts GitHubResourceType = "action-artifacts"
	GitHubResourceTypeDiscussions     GitHubResourceType = "discussions"
	GitHubResourceTypeReleases        GitHubResourceType = "releases"
	GitHubResourceTypeReleaseAssets   GitHubResourceType = "release-assets"
	GitHubResourceTypeGists           GitHubResourceType = "gists"
)

// AllGitHubResourceTypes is the canonical list of valid GitHub resource types.
var AllGitHubResourceTypes = []GitHubResourceType{
	GitHubResourceTypeRepos,
	GitHubResourceTypeForks,
	GitHubResourceTypePRs,
	GitHubResourceTypePRComments,
	GitHubResourceTypeIssues,
	GitHubResourceTypeIssueComments,
	GitHubResourceTypeActions,
	GitHubResourceTypeActionArtifacts,
	GitHubResourceTypeDiscussions,
	GitHubResourceTypeReleases,
	GitHubResourceTypeReleaseAssets,
	GitHubResourceTypeGists,
}

// GitHubResourceSet tracks which resource types are enabled for scanning.
type GitHubResourceSet map[GitHubResourceType]bool

// Has reports whether the set contains the given resource type.
func (rs GitHubResourceSet) Has(r GitHubResourceType) bool { return rs[r] }

// HasAnyIssueOrPR reports whether any issue, PR, or comment resource is enabled (C4).
func (rs GitHubResourceSet) HasAnyIssueOrPR() bool {
	return rs[GitHubResourceTypeIssues] || rs[GitHubResourceTypePRs] ||
		rs[GitHubResourceTypeIssueComments] || rs[GitHubResourceTypePRComments]
}

func (rs GitHubResourceSet) String() string {
	var out []string
	for rt := range rs {
		out = append(out, string(rt))
	}
	return strings.Join(out, ",")
}

// defaultScanResources lists the default resource types each URL kind scans.
var defaultScanResources = map[string][]GitHubResourceType{
	"owner":       {GitHubResourceTypeRepos},
	"repo":        {GitHubResourceTypeRepos},
	"issue":       {GitHubResourceTypeIssues, GitHubResourceTypeIssueComments},
	"pr":          {GitHubResourceTypePRs, GitHubResourceTypePRComments},
	"discussion":  {GitHubResourceTypeDiscussions},
	"release":     {GitHubResourceTypeReleases, GitHubResourceTypeReleaseAssets},
	"actions_run": {GitHubResourceTypeActions, GitHubResourceTypeActionArtifacts},
	"gist":        {GitHubResourceTypeGists},
}

func (s *GitHub) logScanStart() {
	logging.Info().
		Str("target", s.URL).
		Stringer("resources", s.Resources).
		Msg("starting GitHub scan")
}

// Validate checks the GitHub source configuration and populates Resources if needed.
func (s *GitHub) Validate() error {
	if s.URL == "" {
		return errors.New("target URL is required")
	}

	parsed, err := ParseGitHubURL(s.URL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	// Resolve Resources unless the caller pre-populated them.
	if len(s.Resources) == 0 {
		valid := make(map[GitHubResourceType]bool, len(AllGitHubResourceTypes))
		for _, rt := range AllGitHubResourceTypes {
			valid[rt] = true
		}
		rs := make(GitHubResourceSet)
		for _, rt := range defaultScanResources[parsed.Resource] {
			rs[rt] = true
		}
		for _, name := range s.Include {
			rt := GitHubResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			rs[rt] = true
		}
		excluded := make(map[GitHubResourceType]bool)
		for _, name := range s.Exclude {
			rt := GitHubResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			excluded[rt] = true
			delete(rs, rt)
		}
		if rs[GitHubResourceTypeReleases] && !excluded[GitHubResourceTypeReleaseAssets] {
			rs[GitHubResourceTypeReleaseAssets] = true
		}
		s.Resources = rs
	}

	// Token rules (URL-targeted only).
	if s.Token != "" {
		return nil
	}
	switch parsed.Resource {
	case "owner":
		return errors.New("a token is required to scan an organization or user")
	case "repo":
		for rt := range s.Resources {
			if rt != GitHubResourceTypeRepos && rt != GitHubResourceTypeForks {
				return fmt.Errorf("a token is required for API-based resources; only repos and forks can be scanned without a token")
			}
		}
		return nil
	default: // any specific resource URL
		return errors.New("a token is required to scan a specific resource URL")
	}
}

// Fragments enumerates GitHub repos and scans each one.
func (s *GitHub) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if err := s.Validate(); err != nil {
		return err
	}
	s.logScanStart()

	start := time.Now()
	s.restRetry = httpclient.NewRetryTransport(nil)
	s.restRetry.Decider = githubRetryDecider
	s.restRetry.StateExtractor = githubRateLimitStateExtractor

	target, direct, err := s.dispatchURL(ctx, s.URL)
	if err != nil {
		return err
	}

	client := s.newClient(ctx)
	s.gqlClient = s.newGraphQLClient(ctx)
	s.gqlSem = make(chan struct{}, 10)

	if direct {
		return s.scanURL(ctx, client, s.URL, yield)
	}

	scanCtx, cancelScans := context.WithCancel(ctx)
	defer cancelScans()

	var scanGroup errgroup.Group
	scanGroup.SetLimit(100)

	if target.Resource == "user" && s.Resources.Has(GitHubResourceTypeGists) {
		scanGroup.Go(func() error {
			return s.scanUserGists(scanCtx, client, target.Owner, yield)
		})
		if !s.Resources.Has(GitHubResourceTypeRepos) {
			return scanGroup.Wait()
		}

	}

	repoCh, enumErrCh := s.enumerateRepos(ctx, client, target)
	var repoCount atomic.Int64
	for repo := range repoCh {
		repoCount.Add(1)
		scanGroup.Go(func() error {
			return s.scanRepo(scanCtx, client, repo, yield)
		})
	}
	enumErr := <-enumErrCh
	if enumErr != nil {
		cancelScans()
		scanErr := scanGroup.Wait()
		combined := fmt.Errorf("enumerate repos: %w", enumErr)
		if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
			combined = errors.Join(combined, scanErr)
		}
		return combined
	}
	logging.Info().
		Int64("repos", repoCount.Load()).
		Dur("enumeration_ms", time.Since(start)).
		Msg("enumeration complete, waiting for scans")

	scanErr := scanGroup.Wait()
	logging.Info().
		Int64("repos", repoCount.Load()).
		Dur("duration", time.Since(start)).
		Msg("scan complete")

	return scanErr
}

// dispatchURL resolves a raw GitHub URL into either a direct resource scan or
// a repository-enumeration target. It does not mutate GitHub target state.
func (s *GitHub) dispatchURL(ctx context.Context, rawURL string) (*ParsedGitHubURL, bool, error) {
	parsed, err := ParseGitHubURL(rawURL)
	if err != nil {
		return nil, false, fmt.Errorf("invalid target URL: %w", err)
	}
	if s.BaseURL == "" {
		s.BaseURL = baseURLFromHost(parsed.Host)
	}

	switch parsed.Resource {
	case "owner":
		client := s.newClient(ctx)
		ownerType, err := s.resolveOwnerType(ctx, client, parsed.Owner)
		if err != nil {
			return nil, false, err
		}
		if ownerType == "Organization" {
			parsed.Resource = "org"
		} else {
			parsed.Resource = "user"
		}
		logging.Info().Str("owner", parsed.Owner).Str("type", ownerType).Msg("resolved target")
		return parsed, false, nil
	case "repo":
		return parsed, false, nil
	default:
		return parsed, true, nil
	}
}

// enumerateRepos streams repos for a URL-derived repo, org, or user target.
func (s *GitHub) enumerateRepos(ctx context.Context, client *github.Client, target *ParsedGitHubURL) (<-chan *github.Repository, <-chan error) {
	ch := make(chan *github.Repository, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(ch)
		defer close(errCh)

		seen := make(map[string]bool)
		send := func(r *github.Repository) {
			name := r.GetFullName()
			if seen[name] {
				return
			}
			if !s.Resources.Has(GitHubResourceTypeForks) && r.GetFork() {
				return
			}
			if s.isExcluded(name) {
				logging.Debug().Str("repo", name).Msg("excluding repo")
				return
			}
			seen[name] = true
			select {
			case ch <- r:
			case <-ctx.Done():
			}
		}

		switch target.Resource {
		case "repo":
			slug := target.Owner + "/" + target.Repo
			logging.Debug().Str("repo", slug).Msg("fetching repo metadata")
			repo, err := s.fetchRepo(ctx, client, target.Owner, target.Repo)
			if err != nil {
				errCh <- fmt.Errorf("fetch repo %s: %w", slug, err)
				return
			}
			send(repo)
		case "org":
			logging.Info().Str("org", target.Owner).Msg("enumerating org repos")
			err := s.streamRepos(target.Owner, func(page int) ([]*github.Repository, *github.Response, error) {
				return client.Repositories.ListByOrg(ctx, target.Owner, &github.RepositoryListByOrgOptions{
					Type: "all", ListOptions: github.ListOptions{PerPage: itemsPerPage, Page: page},
				})
			}, send)
			if err != nil {
				errCh <- fmt.Errorf("list org %s repos: %w", target.Owner, err)
				return
			}
		case "user":
			logging.Info().Str("user", target.Owner).Msg("enumerating user repos")
			err := s.streamRepos(target.Owner, func(page int) ([]*github.Repository, *github.Response, error) {
				return client.Repositories.ListByUser(ctx, target.Owner, &github.RepositoryListByUserOptions{
					Type: "all", ListOptions: github.ListOptions{PerPage: itemsPerPage, Page: page},
				})
			}, send)
			if err != nil {
				errCh <- fmt.Errorf("list user %s repos: %w", target.Owner, err)
				return
			}
		default:
			errCh <- fmt.Errorf("unsupported repository enumeration target %q", target.Resource)
			return
		}

		errCh <- nil
	}()

	return ch, errCh
}

// scanRepo runs all scans for a single repo under the shared top-level worker pool.
// Git history remains non-fatal; API-backed scans still return errors.
func (s *GitHub) scanRepo(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	name := repo.GetFullName()
	logger := logging.With().Str("repo", name).Logger()
	repoAttrs := s.repoAttributes(repo, "")

	if s.ShouldSkip != nil && s.ShouldSkip(s.repoAttributes(repo, ResourceGitHubRepo)) {
		logger.Debug().Msg("skipping repository based on prefilter")
		return nil
	}

	ghYield := s.wrapYieldWithAttrs(repoAttrs, yield)

	// run wraps every resource scan: logs start/finish and propagates errors.
	// Non-fatal callers (git) call run but discard the return value (C3).
	run := func(label string, fn func() error) error {
		logger.Info().Str("resource", label).Msg("scanning")
		if err := fn(); err != nil {
			logger.Error().Err(err).Msg(label + " scan failed")
			return err
		}
		ev := logger.Info().Str("resource", label)
		if remaining := s.gqlRemaining.Load(); remaining > 0 {
			ev = ev.Int64("gql_remaining", remaining)
		}
		if resetAt := s.gqlResetAt.Load(); resetAt > 0 {
			// ev = ev.Time("gql_reset", time.Unix(resetAt, 0))
			resetTime := time.Unix(resetAt, 0)
			if d := time.Until(resetTime); d > 0 {
				ev = ev.Str("gql_resets_in", d.Round(time.Second).String())
			} else {
				ev = ev.Str("gql_resets_in", "0s")
			}

		}
		ev.Msg("completed")
		return nil
	}

	if s.Resources.Has(GitHubResourceTypeRepos) {
		_ = run(string(GitHubResourceTypeRepos), func() error { return s.scanRepoGit(ctx, repo, ghYield) })
	}
	if s.Resources.Has(GitHubResourceTypeActions) {
		if err := run("actions", func() error { return s.scanActions(ctx, client, repo, ghYield) }); err != nil {
			return err
		}
	}
	if s.Resources.HasAnyIssueOrPR() { // C4
		if err := run("issues_prs", func() error { return s.scanIssuesAndPRsGraphQL(ctx, repo, ghYield) }); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitHubResourceTypeDiscussions) {
		if err := run("discussions", func() error { return s.scanDiscussions(ctx, repo, ghYield) }); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitHubResourceTypeReleases) {
		if err := run("releases", func() error { return s.scanReleases(ctx, client, repo, ghYield) }); err != nil {
			return err
		}
	}

	return nil
}

// wrapYieldWithAttrs returns a yield function that stamps attrs on every fragment,
// applies ShouldSkip, and serializes calls through a mutex.
func (s *GitHub) wrapYieldWithAttrs(attrs map[string]string, yield FragmentsFunc) FragmentsFunc {
	var mu sync.Mutex
	return func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range attrs {
				if v == "" || fragment.Attr(k) != "" {
					continue
				}
				fragment.SetAttr(k, v)
			}
			if s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
				return nil
			}
		}
		mu.Lock()
		defer mu.Unlock()
		return yield(fragment, err)
	}
}

// inDateRange returns true if t falls within the configured Since/Until window.
// Returns "skip" (before Since), "stop" (after Since in DESC order = early termination),
// or "ok". For ascending-order results, callers should treat "stop" as "skip".
func (s *GitHub) inDateRange(t time.Time) (ok bool, terminate bool) {
	if !s.DateRangeOpts.Since.IsZero() && t.Before(s.DateRangeOpts.Since) {
		return false, true // older than Since in DESC order = done
	}
	if !s.DateRangeOpts.Until.IsZero() && !t.Before(s.DateRangeOpts.Until) {
		return false, false // newer than Until = skip
	}
	return true, false
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

// fetchRepo gets a single repo by owner/name.
func (s *GitHub) fetchRepo(ctx context.Context, client *github.Client, owner, name string) (*github.Repository, error) {
	repo, _, err := client.Repositories.Get(ctx, owner, name)
	return repo, err
}

// streamRepos paginates a repo listing endpoint, calling send for each repo.
func (s *GitHub) streamRepos(label string,
	listFn func(page int) ([]*github.Repository, *github.Response, error),
	send func(*github.Repository),
) error {
	page, total := 1, 0
	for {
		repos, resp, err := listFn(page)
		if err != nil {
			return err
		}
		for _, r := range repos {
			send(r)
		}
		total += len(repos)
		evt := logging.Info().Str("target", label).Int("page", page)
		if resp.LastPage > 0 {
			evt = evt.Int("total_pages", resp.LastPage)
		}
		evt.Int("repos_so_far", total).Msg("enumerating repos")
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return nil
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

func (s *GitHub) downloadAndScan(ctx context.Context, rawURL string, reader io.ReadCloser, path string, attrs map[string]string, bearerToken string, yield FragmentsFunc) error {
	return downloadAndScanSource(ctx, sourceDownloadOptions{
		URL:             rawURL,
		Reader:          reader,
		Path:            path,
		Attrs:           attrs,
		BearerToken:     bearerToken,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
		TempPattern:     "betterleaks-download-*",
	}, yield)
}

// apiHost returns the host the GitHub bearer token is scoped to (REST / GraphQL).
// It falls back to api.github.com when not using GitHub Enterprise or when BaseURL
// cannot be parsed.
func (s *GitHub) apiHost() string {
	if s.BaseURL == "" {
		return "api.github.com"
	}
	u, err := url.Parse(s.BaseURL)
	if err != nil || u.Host == "" {
		return "api.github.com"
	}
	return u.Host
}

// newClient creates a GitHub API client with optional token auth and GHE support.
// Fragments must have initialized s.restRetry before calling this.
func (s *GitHub) newClient(ctx context.Context) *github.Client {
	if s.restRetry == nil {
		s.restRetry = httpclient.NewRetryTransport(nil)
		s.restRetry.Decider = githubRetryDecider
		s.restRetry.StateExtractor = githubRateLimitStateExtractor
	}
	httpClient := httpclient.NewAuthenticatedClient(s.Token, s.restRetry, s.apiHost())
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
	return scm.CloneToTempDir(ctx, repo.GetCloneURL(), s.Token, "betterleaks-github-*", scm.CloneOptions{Mirror: true}, func(repoPath string) error {
		var src Source
		if s.Workers > 0 {
			src = &ParallelGit{
				RepoPath: repoPath, ShouldSkip: s.ShouldSkip,
				Platform: scm.GitHubPlatform, RemoteURL: repo.GetHTMLURL(),
				Sema: s.Sema, MaxArchiveDepth: s.MaxArchiveDepth,
				LogOpts: s.LogOpts, Workers: s.Workers,
			}
		} else {
			gitCmd, err := NewGitLogCmdContext(ctx, repoPath, s.LogOpts)
			if err != nil {
				return err
			}
			src = &Git{
				Cmd: gitCmd, ShouldSkip: s.ShouldSkip,
				Platform: scm.GitHubPlatform, RemoteURL: repo.GetHTMLURL(),
				Sema: s.Sema, MaxArchiveDepth: s.MaxArchiveDepth,
			}
		}
		return src.Fragments(ctx, yield)
	})
}

// scanActions scans workflow run logs (and optionally artifacts) for a repo.
func (s *GitHub) scanActions(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	workers := defaultActionsWorkers
	if workers < 1 {
		workers = 1
	}

	runs := make(chan *github.WorkflowRun, workers)
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(runs)
		return s.streamWorkflowRuns(gctx, client, owner, repoName, func(run *github.WorkflowRun) error {
			select {
			case <-gctx.Done():
				return gctx.Err()
			case runs <- run:
				return nil
			}
		})
	})

	for range workers {
		g.Go(func() error {
			for {
				select {
				case <-gctx.Done():
					return nil
				case run, ok := <-runs:
					if !ok {
						return nil
					}
					if err := s.scanRunLogs(gctx, client, owner, repoName, run, yield); err != nil {
						if !isGitHubGone(err) {
							logging.Error().Err(err).Int64("run_id", run.GetID()).Msg("could not scan run logs")
							return fmt.Errorf("scan run %d logs: %w", run.GetID(), err)
						}
					}
					if s.Resources.Has(GitHubResourceTypeActionArtifacts) {
						if err := s.scanRunArtifacts(gctx, client, owner, repoName, run, yield); err != nil {
							if !isGitHubGone(err) {
								logging.Error().Err(err).Int64("run_id", run.GetID()).Msg("could not scan run artifacts")
								return fmt.Errorf("scan run %d artifacts: %w", run.GetID(), err)
							}
						}
					}
				}
			}
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("list workflow runs: %w", err)
	}
	return nil
}

// streamWorkflowRuns lists runs for a repo, respecting date-range and workflow filters.
func (s *GitHub) streamWorkflowRuns(ctx context.Context, client *github.Client, owner, repo string, send func(*github.WorkflowRun) error) error {
	opts := &github.ListWorkflowRunsOptions{
		ListOptions: github.ListOptions{PerPage: itemsPerPage},
	}
	switch {
	case !s.DateRangeOpts.Since.IsZero() && !s.DateRangeOpts.Until.IsZero():
		opts.Created = s.DateRangeOpts.Since.UTC().Format("2006-01-02") + ".." + s.DateRangeOpts.Until.UTC().Format("2006-01-02")
	case !s.DateRangeOpts.Since.IsZero():
		opts.Created = ">=" + s.DateRangeOpts.Since.UTC().Format("2006-01-02")
	case !s.DateRangeOpts.Until.IsZero():
		opts.Created = "<=" + s.DateRangeOpts.Until.UTC().Format("2006-01-02")
	}

	// If specific workflows are requested, fetch runs for each and merge.
	// Copy opts per workflow so paginateWorkflowRuns' Page mutation
	// doesn't carry over to the next workflow.
	if len(s.Actions.Workflows) > 0 {
		for _, wf := range s.Actions.Workflows {
			wfOpts := *opts // copy to avoid Page mutation leaking across workflows
			if err := s.paginateWorkflowRuns(ctx, client, owner, repo, wf, &wfOpts, send); err != nil {
				return err
			}
		}
		return nil
	}

	return s.paginateWorkflowRuns(ctx, client, owner, repo, "", opts, send)
}

func (s *GitHub) paginateWorkflowRuns(ctx context.Context, client *github.Client, owner, repo, workflow string, opts *github.ListWorkflowRunsOptions, send func(*github.WorkflowRun) error) error {
	for {
		var (
			result *github.WorkflowRuns
			resp   *github.Response
			err    error
		)
		if workflow != "" {
			result, resp, err = client.Actions.ListWorkflowRunsByFileName(ctx, owner, repo, workflow, opts)
		} else {
			result, resp, err = client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
		}
		if err != nil {
			return err
		}
		for _, run := range result.WorkflowRuns {
			if err := send(run); err != nil {
				return err
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
}

func runAttrs(run *github.WorkflowRun) map[string]string {
	return map[string]string{
		AttrGitHubActionsRunID:   strconv.FormatInt(run.GetID(), 10),
		AttrGitHubActionsRunName: run.GetName(),
		AttrGitHubActionsRunURL:  run.GetHTMLURL(),
		AttrGitHubActionsEvent:   run.GetEvent(),
		AttrResource:             ResourceGitHubActions,
	}
}

// scanRunLogs downloads the logs zip for a workflow run and scans it.
func (s *GitHub) scanRunLogs(ctx context.Context, client *github.Client, owner, repo string, run *github.WorkflowRun, yield FragmentsFunc) error {
	logURL, _, err := client.Actions.GetWorkflowRunLogs(ctx, owner, repo, run.GetID(), 3)
	if err != nil {
		return err
	}
	runID := strconv.FormatInt(run.GetID(), 10)
	return s.downloadAndScan(ctx, logURL.String(), nil, "actions/logs/run_"+runID+".zip", runAttrs(run), "", yield)
}

// scanRunArtifacts lists and scans all artifacts for a workflow run.
func (s *GitHub) scanRunArtifacts(ctx context.Context, client *github.Client, owner, repo string, run *github.WorkflowRun, yield FragmentsFunc) error {
	attrs := runAttrs(run)
	opts := &github.ListOptions{PerPage: itemsPerPage}
	for {
		artifacts, resp, err := client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, run.GetID(), opts)
		if err != nil {
			return err
		}
		for _, artifact := range artifacts.Artifacts {
			if artifact.GetExpired() {
				continue
			}
			artifactURL, _, err := client.Actions.DownloadArtifact(ctx, owner, repo, artifact.GetID(), 3)
			if err != nil {
				logging.Error().Err(err).Str("artifact", artifact.GetName()).Msg("could not get artifact download URL")
				continue
			}
			path := fmt.Sprintf("actions/artifacts/%s/run_%s.zip", artifact.GetName(), attrs[AttrGitHubActionsRunID])
			if err := s.downloadAndScan(ctx, artifactURL.String(), nil, path, attrs, "", yield); err != nil {
				logging.Error().Err(err).Str("artifact", artifact.GetName()).Msg("could not scan artifact")
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
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
	msg := err.Error()
	return strings.Contains(msg, " 404 ") || strings.Contains(msg, " 410 ")
}

type ghPageInfo struct {
	HasNextPage bool
	EndCursor   githubv4.String
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
}

// ghIssueCommentsTailQuery fetches more comments for one issue when the first page didn't cover all.
type ghIssueCommentsTailQuery struct {
	Repository struct {
		Issue struct {
			Comments ghCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"issue(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
}

// ghPRCommentsTailQuery fetches more issue-style comments for one PR.
type ghPRCommentsTailQuery struct {
	Repository struct {
		PullRequest struct {
			Comments ghCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
}

// ghPRReviewThreadsTailQuery fetches more review threads for one PR (when >50 threads).
type ghPRReviewThreadsTailQuery struct {
	Repository struct {
		PullRequest struct {
			ReviewThreads ghReviewThreadConnection `graphql:"reviewThreads(first: $threadsFirst, after: $threadsAfter)"`
		} `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
}

// ghThreadCommentsTailQuery fetches more comments for one review thread (when a thread has >50 comments).
type ghThreadCommentsTailQuery struct {
	Node struct {
		Thread struct {
			Comments ghCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"... on PullRequestReviewThread"`
	} `graphql:"node(id: $threadId)"`
}

// newGraphQLClient constructs a githubv4 client with optional token auth and GHE support.
func (s *GitHub) newGraphQLClient(ctx context.Context) *githubv4.Client {
	// Reuse RetryTransport so GraphQL can honor Retry-After on secondary rate
	// limits and share the same backoff behavior as REST.
	s.gqlRetry = httpclient.NewRetryTransport(nil)
	s.gqlRetry.Decider = githubRetryDecider
	s.gqlRetry.StateExtractor = githubRateLimitStateExtractor
	httpClient := httpclient.NewAuthenticatedClient(s.Token, s.gqlRetry, s.apiHost())
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

// gqlQuery executes a single GraphQL call, bounded by s.gqlSem so at most 10
// round-trips are in flight concurrently. HTTP-level 429s with Retry-After are
// handled by s.gqlRetry. Primary GraphQL rate limits (HTTP 200 with an error
// body) are detected here: the transport pause is set so every goroutine waits
// before its next request, then this goroutine sleeps and retries.
// For guidance look at https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api
func (s *GitHub) gqlQuery(ctx context.Context, q any, vars map[string]any) error {
	for {
		// Acquire a concurrency slot.
		select {
		case s.gqlSem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		err := s.gqlClient.Query(ctx, q, vars)
		<-s.gqlSem // release slot regardless of outcome

		if err == nil {
			// Snapshot the latest rate-limit budget for the completion logger.
			if r := s.gqlRetry.RateLimitRemaining(); r > 0 {
				s.gqlRemaining.Store(r)
			}
			if rt := s.gqlRetry.RateLimitReset(); !rt.IsZero() {
				s.gqlResetAt.Store(rt.Unix())
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !isGQLRateLimitErr(err) {
			return err
		}

		// Primary rate limit: GitHub returned HTTP 200 with a GraphQL error.
		// X-RateLimit-Reset was recorded by the transport on the response.
		wait := 60 * time.Second
		if reset := s.gqlRetry.RateLimitReset(); !reset.IsZero() {
			if d := time.Until(reset) + 2*time.Second; d > 0 {
				wait = d
			}
		}

		// Propagate the pause into the transport so every other goroutine's
		// next RoundTrip call blocks in waitForResume for the same duration.
		s.gqlRetry.PauseFor(wait)

		logging.Warn().
			Err(err).
			Str("wait", wait.Round(time.Second).String()).
			Time("resume_at", time.Now().Add(wait).Round(time.Second)).
			Msg("GraphQL rate limited, pausing")

		// Sleep without holding a semaphore slot — there is nothing useful to
		// do while we wait, and holding it would reduce available concurrency.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		// Loop: re-acquire a slot and retry.
	}
}

// isGQLRateLimitErr reports whether a githubv4 query error represents a GitHub
// rate-limit response (primary or secondary). These arrive as HTTP 200 with a
// GraphQL "errors" body rather than a 429, so the transport cannot intercept them.
func isGQLRateLimitErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "rate limit") || strings.Contains(msg, "abuse")
}

func githubRetryDecider(req *http.Request, resp *http.Response, err error, now time.Time) (bool, time.Duration) {
	retry, wait := httpclient.DefaultRetryDecider(req, resp, err, now)
	if retry {
		return retry, wait
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		return false, 0
	}
	if resp.Header.Get("X-RateLimit-Remaining") != "0" {
		return false, 0
	}
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		if epoch, parseErr := strconv.ParseInt(reset, 10, 64); parseErr == nil {
			if d := time.Unix(epoch, 0).Sub(now); d > 0 {
				return true, d
			}
		}
	}
	return true, 60 * time.Second
}

func githubRateLimitStateExtractor(resp *http.Response) (int64, time.Time, bool) {
	if resp == nil {
		return 0, time.Time{}, false
	}
	remainingRaw := resp.Header.Get("X-RateLimit-Remaining")
	resetRaw := resp.Header.Get("X-RateLimit-Reset")
	if remainingRaw == "" && resetRaw == "" {
		return 0, time.Time{}, false
	}
	var (
		remaining int64
		resetAt   time.Time
	)
	if remainingRaw != "" {
		if parsed, err := strconv.ParseInt(remainingRaw, 10, 64); err == nil {
			remaining = parsed
		}
	}
	if resetRaw != "" {
		if epoch, err := strconv.ParseInt(resetRaw, 10, 64); err == nil && epoch > 0 {
			resetAt = time.Unix(epoch, 0)
		}
	}
	return remaining, resetAt, true
}

// scanIssuesAndPRsGraphQL scans issues, PRs, and comments via the GitHub GraphQL API.
func (s *GitHub) scanIssuesAndPRsGraphQL(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	owner, name := repo.GetOwner().GetLogin(), repo.GetName()
	var (
		issuesAfter  *githubv4.String
		prsAfter     *githubv4.String
		issuesDone   = !s.Resources.Has(GitHubResourceTypeIssues) && !s.Resources.Has(GitHubResourceTypeIssueComments)
		prsDone      = !s.Resources.Has(GitHubResourceTypePRs) && !s.Resources.Has(GitHubResourceTypePRComments)
		commentCount int
	)
	for !issuesDone || !prsDone {
		vars := map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"issuesFirst":   githubv4.Int(gqlIssuesFirst),
			"issuesAfter":   issuesAfter,
			"prsFirst":      githubv4.Int(gqlPRsFirst),
			"prsAfter":      prsAfter,
			"commentsFirst": githubv4.Int(gqlCommentsFirst),
			"threadsFirst":  githubv4.Int(gqlThreadsFirst),
		}
		// If one side is done, ask for zero to keep the query well-formed.
		if issuesDone {
			vars["issuesFirst"] = githubv4.Int(0)
		}
		if prsDone {
			vars["prsFirst"] = githubv4.Int(0)
		}

		var q ghRepoScanQuery
		if err := s.gqlQuery(ctx, &q, vars); err != nil {
			return fmt.Errorf("graphql repo scan: %w", err)
		}
		if !issuesDone {
			for _, issue := range q.Repository.Issues.Nodes {
				if ok, stop := s.inDateRange(issue.CreatedAt); stop {
					issuesDone = true
					break
				} else if !ok {
					continue
				}
				if err := s.emitIssueAndComments(ctx, owner, name, issue, &commentCount, yield); err != nil {
					return err
				}
			}
			if !issuesDone && !q.Repository.Issues.PageInfo.HasNextPage {
				issuesDone = true
			} else if !issuesDone {
				issuesAfter = githubv4.NewString(q.Repository.Issues.PageInfo.EndCursor)
			}
		}

		// Process PRs (same date-range logic).
		if !prsDone {
			for _, pr := range q.Repository.PullRequests.Nodes {
				if ok, stop := s.inDateRange(pr.CreatedAt); stop {
					prsDone = true
					break
				} else if !ok {
					continue
				}
				if err := s.emitPRAndComments(ctx, owner, name, pr, &commentCount, yield); err != nil {
					return err
				}
			}
			if !prsDone && !q.Repository.PullRequests.PageInfo.HasNextPage {
				prsDone = true
			} else if !prsDone {
				prsAfter = githubv4.NewString(q.Repository.PullRequests.PageInfo.EndCursor)
			}
		}
	}

	return nil
}

// itemEmit bundles the parameters for emitItemAndComments (C1).
type itemEmit struct {
	title, body, url, resource string
	numAttr, numVal            string
	bodyRes, commentsRes       GitHubResourceType
	comments                   ghCommentConnection
	fetchTail                  func(githubv4.String) ([]ghComment, ghPageInfo, error)
}

// emitItemAndComments emits a title+body fragment and tail-paginates comments.
// bodyRes gates whether the body is emitted; commentsRes gates comment scanning.
// count tracks comments emitted (caller adds to totalComments).
// Returns true if comments were processed (commentsRes enabled).
func (s *GitHub) emitItemAndComments(it itemEmit, count *int, yield FragmentsFunc) (bool, error) {
	if s.Resources.Has(it.bodyRes) && (it.title != "" || it.body != "") {
		frag := Fragment{Raw: strings.TrimSpace(it.title + "\n" + it.body)}
		frag.SetAttr(AttrURL, it.url)
		frag.SetAttr(AttrResource, it.resource)
		frag.SetAttr(it.numAttr, it.numVal)
		if err := yield(frag, nil); err != nil {
			return false, err
		}
	}
	if !s.Resources.Has(it.commentsRes) {
		return false, nil
	}
	prNum, issueNum := "", ""
	if it.numAttr == AttrGitHubPRNumber {
		prNum = it.numVal
	} else {
		issueNum = it.numVal
	}
	if err := s.emitCommentNodes(it.comments.Nodes, it.url, prNum, issueNum, count, yield); err != nil {
		return true, err
	}
	pi := it.comments.PageInfo
	for pi.HasNextPage {
		nodes, next, err := it.fetchTail(pi.EndCursor)
		if err != nil {
			return true, err
		}
		if err := s.emitCommentNodes(nodes, it.url, prNum, issueNum, count, yield); err != nil {
			return true, err
		}
		pi = next
	}
	return true, nil
}

func (s *GitHub) emitIssueAndComments(ctx context.Context, owner, name string, issue ghIssueNode, totalComments *int, yield FragmentsFunc) error {
	var count int
	_, err := s.emitItemAndComments(itemEmit{
		title: issue.Title, body: issue.Body, url: issue.Url, resource: ResourceGitHubIssue,
		numAttr: AttrGitHubIssueNumber, numVal: strconv.Itoa(issue.Number),
		bodyRes: GitHubResourceTypeIssues, commentsRes: GitHubResourceTypeIssueComments,
		comments: issue.Comments,
		fetchTail: func(cursor githubv4.String) ([]ghComment, ghPageInfo, error) {
			var q ghIssueCommentsTailQuery
			err := s.gqlQuery(ctx, &q, map[string]any{
				"owner": githubv4.String(owner), "repo": githubv4.String(name),
				"number":        githubv4.Int(issue.Number),
				"commentsFirst": githubv4.Int(gqlCommentsTailFirst), "commentsAfter": githubv4.NewString(cursor),
			})
			return q.Repository.Issue.Comments.Nodes, q.Repository.Issue.Comments.PageInfo, err
		},
	}, &count, yield)
	*totalComments += count
	return err
}

func (s *GitHub) emitPRAndComments(ctx context.Context, owner, name string, pr ghPRNode, totalComments *int, yield FragmentsFunc) error {
	var count int
	prNumStr := strconv.Itoa(pr.Number)
	did, err := s.emitItemAndComments(itemEmit{
		title: pr.Title, body: pr.Body, url: pr.Url, resource: ResourceGitHubPR,
		numAttr: AttrGitHubPRNumber, numVal: prNumStr,
		bodyRes: GitHubResourceTypePRs, commentsRes: GitHubResourceTypePRComments,
		comments: pr.Comments,
		fetchTail: func(cursor githubv4.String) ([]ghComment, ghPageInfo, error) {
			var q ghPRCommentsTailQuery
			err := s.gqlQuery(ctx, &q, map[string]any{
				"owner": githubv4.String(owner), "repo": githubv4.String(name),
				"number":        githubv4.Int(pr.Number),
				"commentsFirst": githubv4.Int(gqlCommentsTailFirst), "commentsAfter": githubv4.NewString(cursor),
			})
			return q.Repository.PullRequest.Comments.Nodes, q.Repository.PullRequest.Comments.PageInfo, err
		},
	}, &count, yield)
	if err != nil || !did {
		*totalComments += count
		return err
	}

	// Review thread comments: first page of threads in hand.
	threads := pr.ReviewThreads.Nodes
	threadsCursor := pr.ReviewThreads.PageInfo.EndCursor
	threadsHasMore := pr.ReviewThreads.PageInfo.HasNextPage
	for {
		for _, thread := range threads {
			if err := s.emitCommentNodes(thread.Comments.Nodes, pr.Url, prNumStr, "", &count, yield); err != nil {
				return err
			}
			// Tail-paginate this thread's comments if needed.
			tc := thread.Comments.PageInfo
			for tc.HasNextPage {
				var tq ghThreadCommentsTailQuery
				if err := s.gqlQuery(ctx, &tq, map[string]any{
					"threadId":      thread.Id,
					"commentsFirst": githubv4.Int(gqlCommentsTailFirst),
					"commentsAfter": githubv4.NewString(tc.EndCursor),
				}); err != nil {
					return fmt.Errorf("thread comments tail: %w", err)
				}
				if err := s.emitCommentNodes(tq.Node.Thread.Comments.Nodes, pr.Url, prNumStr, "", &count, yield); err != nil {
					return err
				}
				tc = tq.Node.Thread.Comments.PageInfo
			}
		}
		if !threadsHasMore {
			break
		}
		var ttail ghPRReviewThreadsTailQuery
		if err := s.gqlQuery(ctx, &ttail, map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"number":        githubv4.Int(pr.Number),
			"threadsFirst":  githubv4.Int(gqlThreadsTailFirst),
			"threadsAfter":  githubv4.NewString(threadsCursor),
			"commentsFirst": githubv4.Int(gqlCommentsFirst),
		}); err != nil {
			return fmt.Errorf("pr %d threads tail: %w", pr.Number, err)
		}
		threads = ttail.Repository.PullRequest.ReviewThreads.Nodes
		threadsHasMore = ttail.Repository.PullRequest.ReviewThreads.PageInfo.HasNextPage
		threadsCursor = ttail.Repository.PullRequest.ReviewThreads.PageInfo.EndCursor
	}
	*totalComments += count
	return nil
}

// emitCommentNodes yields one Fragment per comment.
// Either prNum or issueNum should be set; pass "" for the unused one.
func (s *GitHub) emitCommentNodes(comments []ghComment, parentURL, prNum, issueNum string, count *int, yield FragmentsFunc) error {
	for _, c := range comments {
		if c.Body == "" {
			continue
		}
		if ok, _ := s.inDateRange(c.CreatedAt); !ok {
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

// scanReleases scans GitHub Releases for a repo via the REST API.
func (s *GitHub) scanReleases(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	owner, repoName := repo.GetOwner().GetLogin(), repo.GetName()
	// Build httpClient once for the entire scan; passed to emitRelease → scanReleaseAssets (C7).
	httpClient := httpclient.NewAuthenticatedClient(s.Token, s.restRetry, s.apiHost())
	opts := &github.ListOptions{PerPage: itemsPerPage}
	for {
		releases, resp, err := client.Repositories.ListReleases(ctx, owner, repoName, opts)
		if err != nil {
			return fmt.Errorf("list releases: %w", err)
		}
		for _, rel := range releases {
			if ok, stop := s.inDateRange(rel.GetCreatedAt().Time); stop {
				return nil
			} else if !ok {
				continue
			}
			if err := s.emitRelease(ctx, client, httpClient, owner, repoName, rel, yield); err != nil {
				return err
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
}

// emitRelease emits a release body fragment and scans its assets.
func (s *GitHub) emitRelease(ctx context.Context, client *github.Client, httpClient *http.Client, owner, repo string, rel *github.RepositoryRelease, yield FragmentsFunc) error {
	tag := rel.GetTagName()
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
	if s.Resources.Has(GitHubResourceTypeReleaseAssets) {
		if err := s.scanReleaseAssets(ctx, client, httpClient, owner, repo, rel, yield); err != nil {
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
	rel, _, err := client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
	if err != nil {
		return fmt.Errorf("get release %s: %w", tag, err)
	}
	httpClient := httpclient.NewAuthenticatedClient(s.Token, s.restRetry, s.apiHost())
	return s.emitRelease(ctx, client, httpClient, owner, repo, rel, yield)
}

// scanReleaseAssets lists and scans all downloadable assets for a release.
// httpClient is built once by the caller to avoid repeated construction (C7).
func (s *GitHub) scanReleaseAssets(ctx context.Context, client *github.Client, httpClient *http.Client, owner, repo string, rel *github.RepositoryRelease, yield FragmentsFunc) error {
	tag := rel.GetTagName()
	opts := &github.ListOptions{PerPage: itemsPerPage}
	for {
		assets, resp, err := client.Repositories.ListReleaseAssets(ctx, owner, repo, rel.GetID(), opts)
		if err != nil {
			return fmt.Errorf("list release assets for %s: %w", tag, err)
		}
		for _, asset := range assets {
			rc, _, err := client.Repositories.DownloadReleaseAsset(ctx, owner, repo, asset.GetID(), httpClient)
			if err != nil {
				logging.Error().Err(err).Str("tag", tag).Str("asset", asset.GetName()).Msg("could not download release asset")
				continue
			}
			attrs := map[string]string{
				AttrGitHubReleaseTag:       tag,
				AttrGitHubReleaseAssetName: asset.GetName(),
				AttrResource:               ResourceGitHubReleaseAsset,
			}
			if err := s.downloadAndScan(ctx, "", rc, fmt.Sprintf("releases/%s/%s", tag, asset.GetName()), attrs, "", yield); err != nil {
				logging.Error().Err(err).Str("tag", tag).Str("asset", asset.GetName()).Msg("could not scan release asset")
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
}

// scanReleaseSourceArchives downloads and scans the auto-generated source code
// zip and tarball that GitHub attaches to every release.
func (s *GitHub) scanReleaseSourceArchives(ctx context.Context, rel *github.RepositoryRelease, yield FragmentsFunc) error {
	tag := rel.GetTagName()
	for _, a := range []struct{ url, name string }{
		{rel.GetZipballURL(), "source-code.zip"},
		{rel.GetTarballURL(), "source-code.tar.gz"},
	} {
		if a.url == "" {
			continue
		}
		attrs := map[string]string{
			AttrGitHubReleaseTag:       tag,
			AttrGitHubReleaseAssetName: a.name,
			AttrResource:               ResourceGitHubReleaseAsset,
		}
		if err := s.downloadAndScan(ctx, a.url, nil, fmt.Sprintf("releases/%s/%s", tag, a.name), attrs, s.Token, yield); err != nil {
			logging.Error().Err(err).Str("tag", tag).Str("archive", a.name).Msg("could not scan release source archive")
		}
	}
	return nil
}

// scanUserGists scans all public gists for a GitHub user via the REST API.
func (s *GitHub) scanUserGists(ctx context.Context, client *github.Client, user string, yield FragmentsFunc) error {
	opts := &github.GistListOptions{
		ListOptions: github.ListOptions{PerPage: itemsPerPage},
	}
	if !s.DateRangeOpts.Since.IsZero() {
		opts.Since = s.DateRangeOpts.Since
	}
	for {
		gists, resp, err := client.Gists.List(ctx, user, opts)
		if err != nil {
			return fmt.Errorf("list gists for %s: %w", user, err)
		}
		for _, gist := range gists {
			// Gists are returned newest-first; delegate date filtering to
			// inDateRange so logic stays in sync with other resource paths (A8).
			ok, stop := s.inDateRange(gist.GetUpdatedAt().Time)
			if stop {
				return nil
			}
			if !ok {
				continue
			}
			// Pass nil count — the local accumulator was never read (A7).
			if err := s.emitGist(ctx, client, gist.GetID(), gist.GetOwner().GetLogin(), gist.GetHTMLURL(), yield); err != nil {
				logging.Error().Err(err).Str("gist_id", gist.GetID()).Msg("could not scan gist")
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return nil
}

// emitGist fetches a single gist by ID and emits one fragment per file.
func (s *GitHub) emitGist(ctx context.Context, client *github.Client, gistID, owner, htmlURL string, yield FragmentsFunc) error {
	full, _, err := client.Gists.Get(ctx, gistID)
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
	}
	return nil
}

// GraphQL types for discussions.
type ghDiscussionCommentReply struct {
	DatabaseId int64
	Body       string
	Url        string
	CreatedAt  time.Time
	Author     ghActor
}

type ghDiscussionComment struct {
	Id         githubv4.ID
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
}

type ghDiscussionCommentsTailQuery struct {
	Repository struct {
		Discussion struct {
			Comments ghDiscussionCommentConnection `graphql:"comments(first: $commentsFirst, after: $commentsAfter)"`
		} `graphql:"discussion(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
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
}

// scanDiscussions scans GitHub Discussions for a repo via the GraphQL API.
func (s *GitHub) scanDiscussions(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	owner, name := repo.GetOwner().GetLogin(), repo.GetName()
	var (
		after        *githubv4.String
		commentCount int
	)
	for {
		var q ghRepoDiscussionsQuery
		if err := s.gqlQuery(ctx, &q, map[string]any{
			"owner":            githubv4.String(owner),
			"repo":             githubv4.String(name),
			"discussionsFirst": githubv4.Int(gqlIssuesFirst),
			"discussionsAfter": after,
			"commentsFirst":    githubv4.Int(gqlCommentsFirst),
			"repliesFirst":     githubv4.Int(gqlRepliesFirst),
		}); err != nil {
			return fmt.Errorf("graphql discussions: %w", err)
		}
		for _, d := range q.Repository.Discussions.Nodes {
			if ok, stop := s.inDateRange(d.CreatedAt); stop {
				return nil
			} else if !ok {
				continue
			}
			if err := s.emitDiscussion(ctx, owner, name, d, &commentCount, yield); err != nil {
				return err
			}
		}
		if !q.Repository.Discussions.PageInfo.HasNextPage {
			break
		}
		after = githubv4.NewString(q.Repository.Discussions.PageInfo.EndCursor)
	}
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

	var itemComments int
	if err := s.emitDiscussionComments(ctx, d.Url, numStr, d.Comments.Nodes, &itemComments, yield); err != nil {
		return err
	}

	// Tail-paginate comments if needed.
	cursor := d.Comments.PageInfo.EndCursor
	hasMore := d.Comments.PageInfo.HasNextPage
	for hasMore {
		var tail ghDiscussionCommentsTailQuery
		if err := s.gqlQuery(ctx, &tail, map[string]any{
			"owner":         githubv4.String(owner),
			"repo":          githubv4.String(name),
			"number":        githubv4.Int(d.Number),
			"commentsFirst": githubv4.Int(gqlCommentsTailFirst),
			"commentsAfter": githubv4.NewString(cursor),
			"repliesFirst":  githubv4.Int(gqlRepliesFirst),
		}); err != nil {
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

// emitDiscussionReply emits a single discussion reply fragment with date filtering.
func (s *GitHub) emitDiscussionReply(r ghDiscussionCommentReply, discussionURL, discussionNum string, count *int, yield FragmentsFunc) error {
	if r.Body == "" {
		return nil
	}
	if ok, _ := s.inDateRange(r.CreatedAt); !ok {
		return nil
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
	return nil
}

// discussionCommentAsReply converts a ghDiscussionComment into the shared
// reply shape, so emitDiscussionReply can handle both types (C2).
func discussionCommentAsReply(c ghDiscussionComment) ghDiscussionCommentReply {
	return ghDiscussionCommentReply{
		DatabaseId: c.DatabaseId, Body: c.Body, Url: c.Url,
		CreatedAt: c.CreatedAt, Author: c.Author,
	}
}

// emitDiscussionComments emits comments and their replies for a discussion,
// including tail-pagination of replies when the first page is incomplete.
func (s *GitHub) emitDiscussionComments(ctx context.Context, discussionURL, discussionNum string, comments []ghDiscussionComment, count *int, yield FragmentsFunc) error {
	for _, c := range comments {
		// Emit the comment itself via the shared reply helper (C2).
		if err := s.emitDiscussionReply(discussionCommentAsReply(c), discussionURL, discussionNum, count, yield); err != nil {
			return err
		}
		// Emit inline replies + tail-paginate.
		for _, r := range c.Replies.Nodes {
			if err := s.emitDiscussionReply(r, discussionURL, discussionNum, count, yield); err != nil {
				return err
			}
		}
		pi := c.Replies.PageInfo
		for pi.HasNextPage {
			var tail ghDiscussionReplyTailQuery
			if err := s.gqlQuery(ctx, &tail, map[string]any{
				"commentId":    c.Id,
				"repliesFirst": githubv4.Int(gqlRepliesTailFirst),
				"repliesAfter": githubv4.NewString(pi.EndCursor),
			}); err != nil {
				return fmt.Errorf("discussion comment replies tail: %w", err)
			}
			for _, r := range tail.Node.Comment.Replies.Nodes {
				if err := s.emitDiscussionReply(r, discussionURL, discussionNum, count, yield); err != nil {
					return err
				}
			}
			pi = tail.Node.Comment.Replies.PageInfo
		}
	}
	return nil
}

// ParsedGitHubURL holds the components extracted from a GitHub target URL.
type ParsedGitHubURL struct {
	Owner    string // repo owner, org name, user name, or gist user
	Repo     string // repo name (empty for owner-level or gists)
	Resource string // "owner", "repo", "issue", "pr", "actions_run", "release", "discussion", "gist"
	ID       string // number, run ID, tag name, or gist ID (empty for owner/repo targets)
	Host     string // host (for GHE detection)
}

// ParseGitHubURL parses a GitHub URL into its components.
// Supports org/user URLs, repo URLs, specific resource URLs, and gists.
func ParseGitHubURL(rawURL string) (*ParsedGitHubURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}

	host := strings.ToLower(u.Host)

	// Gist: gist.github.com/{user}/{id} or gist.{ghe-host}/{user}/{id}
	if strings.HasPrefix(host, "gist.") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("gist URL must be gist.github.com/{user}/{id}")
		}
		return &ParsedGitHubURL{Owner: parts[0], Resource: "gist", ID: parts[1], Host: host}, nil
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")

	// Owner-level URL: github.com/{owner}
	if len(parts) == 1 && parts[0] != "" {
		return &ParsedGitHubURL{Owner: parts[0], Resource: "owner", Host: host}, nil
	}

	// Repo-level URL: github.com/{owner}/{repo}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return &ParsedGitHubURL{Owner: parts[0], Repo: parts[1], Resource: "repo", Host: host}, nil
	}

	// Specific resource: {host}/{owner}/{repo}/{type}/...
	if len(parts) < 4 {
		return nil, fmt.Errorf("URL must point to a GitHub owner, repo, or specific resource (issue, PR, discussion, release, or action run)")
	}
	owner, repo := parts[0], parts[1]
	kind, id := parts[2], parts[3]

	p := &ParsedGitHubURL{Owner: owner, Repo: repo, Host: host}

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
		// actions/runs/{id} or actions/runs/{id}/job/{jobId}
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

// baseURLFromHost returns the GitHub Enterprise base URL for a given host,
// or empty string for github.com (use default).
func baseURLFromHost(host string) string {
	if host == "github.com" || host == "gist.github.com" {
		return ""
	}
	// Strip gist. prefix for GHE hosts.
	h := strings.TrimPrefix(host, "gist.")
	return "https://" + h
}

// resolveOwnerType determines whether a GitHub login is an Organization or User
// by calling GET /users/{login}. Returns "Organization" or "User".
func (s *GitHub) resolveOwnerType(ctx context.Context, client *github.Client, login string) (string, error) {
	user, _, err := client.Users.Get(ctx, login)
	if err != nil {
		return "", fmt.Errorf("resolve owner %q: %w", login, err)
	}
	return user.GetType(), nil
}

// scanURL dispatches to the appropriate single-resource scanner based on the URL.
func (s *GitHub) scanURL(ctx context.Context, client *github.Client, rawURL string, yield FragmentsFunc) error {
	parsed, err := ParseGitHubURL(rawURL)
	if err != nil {
		return fmt.Errorf("--url: %w", err)
	}

	// For repo-level resources, fetch repo metadata and stamp it on all fragments.
	if parsed.Resource != "gist" {
		repo, err := s.fetchRepo(ctx, client, parsed.Owner, parsed.Repo)
		if err != nil {
			return fmt.Errorf("fetch repo %s/%s: %w", parsed.Owner, parsed.Repo, err)
		}
		yield = s.wrapYieldWithAttrs(s.repoAttributes(repo, ""), yield)
	}

	owner, repo := parsed.Owner, parsed.Repo

	switch parsed.Resource {
	case "issue":
		num, err := strconv.Atoi(parsed.ID)
		if err != nil {
			return fmt.Errorf("invalid issue number %q", parsed.ID)
		}
		var q ghSingleIssueQuery
		vars := map[string]any{
			"owner": githubv4.String(owner), "repo": githubv4.String(repo),
			"number": githubv4.Int(num), "commentsFirst": githubv4.Int(gqlCommentsFirst),
		}
		if err := s.gqlQuery(ctx, &q, vars); err != nil {
			return fmt.Errorf("fetch issue %d: %w", num, err)
		}
		var dummy int
		return s.emitIssueAndComments(ctx, owner, repo, q.Repository.Issue, &dummy, yield)

	case "pr":
		num, err := strconv.Atoi(parsed.ID)
		if err != nil {
			return fmt.Errorf("invalid PR number %q", parsed.ID)
		}
		var q ghSinglePRQuery
		vars := map[string]any{
			"owner": githubv4.String(owner), "repo": githubv4.String(repo),
			"number": githubv4.Int(num), "commentsFirst": githubv4.Int(gqlCommentsFirst),
			"threadsFirst": githubv4.Int(gqlThreadsFirst),
		}
		if err := s.gqlQuery(ctx, &q, vars); err != nil {
			return fmt.Errorf("fetch pr %d: %w", num, err)
		}
		var dummy int
		return s.emitPRAndComments(ctx, owner, repo, q.Repository.PullRequest, &dummy, yield)

	case "discussion":
		num, err := strconv.Atoi(parsed.ID)
		if err != nil {
			return fmt.Errorf("invalid discussion number %q", parsed.ID)
		}
		var q ghSingleDiscussionQuery
		vars := map[string]any{
			"owner": githubv4.String(owner), "repo": githubv4.String(repo),
			"number": githubv4.Int(num), "commentsFirst": githubv4.Int(gqlCommentsFirst),
			"repliesFirst": githubv4.Int(gqlRepliesFirst),
		}
		if err := s.gqlQuery(ctx, &q, vars); err != nil {
			return fmt.Errorf("fetch discussion %d: %w", num, err)
		}
		var dummy int
		return s.emitDiscussion(ctx, owner, repo, q.Repository.Discussion, &dummy, yield)

	case "release":
		return s.scanSingleRelease(ctx, client, owner, repo, parsed.ID, yield)

	case "actions_run":
		runID, err := strconv.ParseInt(parsed.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid run ID %q", parsed.ID)
		}
		return s.scanSingleActionRun(ctx, client, owner, repo, runID, yield)

	case "gist":
		return s.emitGist(ctx, client, parsed.ID, parsed.Owner, rawURL, yield)
	}
	return nil
}

type ghSingleIssueQuery struct {
	Repository struct {
		Issue ghIssueNode `graphql:"issue(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
}

type ghSinglePRQuery struct {
	Repository struct {
		PullRequest ghPRNode `graphql:"pullRequest(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
}

type ghSingleDiscussionQuery struct {
	Repository struct {
		Discussion ghDiscussionNode `graphql:"discussion(number: $number)"`
	} `graphql:"repository(owner: $owner, name: $repo)"`
}

// scanSingleActionRun scans logs (and optionally artifacts) for one workflow run.
func (s *GitHub) scanSingleActionRun(ctx context.Context, client *github.Client, owner, repo string, runID int64, yield FragmentsFunc) error {
	run, _, err := client.Actions.GetWorkflowRunByID(ctx, owner, repo, runID)
	if err != nil {
		return fmt.Errorf("get action run %d: %w", runID, err)
	}
	if err := s.scanRunLogs(ctx, client, owner, repo, run, yield); err != nil {
		if !isGitHubGone(err) {
			return err
		}
	}
	if s.Resources.Has(GitHubResourceTypeActionArtifacts) {
		return s.scanRunArtifacts(ctx, client, owner, repo, run, yield)
	}
	return nil
}
