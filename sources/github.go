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
	logging.Info().
		Int("repos", len(repos)).
		Dur("total_ms", time.Since(start)).
		Msg("GitHub scan complete")
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
// If actions scanning is enabled, it also scans workflow run logs and artifacts.
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
	ghYield := func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range repoAttrs {
				if v == "" || fragment.Attr(k) != "" {
					continue
				}
				fragment.SetAttr(k, v)
			}
		}
		return yield(fragment, err)
	}

	gitStart := time.Now()
	if err := s.scanRepoGit(ctx, repo, ghYield); err != nil {
		logger.Error().Err(err).Msg("git scan failed")
	} else {
		logger.Debug().Dur("git_ms", time.Since(gitStart)).Msg("git scan complete")
	}

	if s.ScanActions {
		actionsStart := time.Now()
		if err := s.scanActions(ctx, client, repo, ghYield); err != nil {
			logger.Error().Err(err).Msg("actions scan failed")
		} else {
			logger.Debug().Dur("actions_ms", time.Since(actionsStart)).Msg("actions scan complete")
		}
	}

	if s.ScanIssues || s.ScanPRs || s.ScanComments {
		logger.Info().
			Bool("issues", s.ScanIssues).
			Bool("prs", s.ScanPRs).
			Bool("comments", s.ScanComments).
			Int("issues_max", s.IssueOpts.MaxIssues).
			Int("comments_max", s.IssueOpts.MaxComments).
			Msg("scanning issues, prs, and comments")
		issuesStart := time.Now()
		if err := s.scanIssuesAndPRs(ctx, client, repo, ghYield); err != nil {
			logger.Error().Err(err).Msg("issues/prs scan failed")
		} else {
			logger.Debug().Dur("issues_prs_ms", time.Since(issuesStart)).Msg("issues/prs scan complete")
		}
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

type githubIssuePager struct {
	client *github.Client
	owner  string
	repo   string
	opts   *github.IssueListByRepoOptions
	items  []*github.Issue
	index  int
	done   bool
}

func (p *githubIssuePager) Next(ctx context.Context, s *GitHub) (*github.Issue, error) {
	for {
		if p.index < len(p.items) {
			item := p.items[p.index]
			p.index++
			if item.IsPullRequest() {
				continue
			}
			return item, nil
		}
		if p.done {
			return nil, nil
		}

		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			p.items, resp, err = p.client.Issues.ListByRepo(ctx, p.owner, p.repo, p.opts)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("list issues: %w", err)
		}

		p.index = 0
		if resp.NextPage == 0 {
			p.done = true
		} else {
			p.opts.ListOptions.Page = resp.NextPage
		}
		if len(p.items) == 0 && p.done {
			return nil, nil
		}
	}
}

type githubPRPager struct {
	client *github.Client
	owner  string
	repo   string
	opts   *github.PullRequestListOptions
	items  []*github.PullRequest
	index  int
	done   bool
}

func (p *githubPRPager) Next(ctx context.Context, s *GitHub) (*github.PullRequest, error) {
	for {
		if p.index < len(p.items) {
			item := p.items[p.index]
			p.index++
			return item, nil
		}
		if p.done {
			return nil, nil
		}

		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			p.items, resp, err = p.client.PullRequests.List(ctx, p.owner, p.repo, p.opts)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("list pull requests: %w", err)
		}

		p.index = 0
		if resp.NextPage == 0 {
			p.done = true
		} else {
			p.opts.ListOptions.Page = resp.NextPage
		}
		if len(p.items) == 0 && p.done {
			return nil, nil
		}
	}
}

// scanIssuesAndPRs scans issue and PR bodies, plus issue comments when enabled.
func (s *GitHub) scanIssuesAndPRs(ctx context.Context, client *github.Client, repo *github.Repository, yield FragmentsFunc) error {
	owner := repo.GetOwner().GetLogin()
	repoName := repo.GetName()
	logger := logging.With().Str("repo", repo.GetFullName()).Logger()
	start := time.Now()
	workerLimit := min(8, max(1, runtime.NumCPU()/2))
	needIssues := s.ScanIssues || s.ScanComments
	needPRs := s.ScanPRs || s.ScanComments

	var issuePager *githubIssuePager
	if needIssues {
		issuePager = &githubIssuePager{
			client: client,
			owner:  owner,
			repo:   repoName,
			opts: &github.IssueListByRepoOptions{
				State:       "all",
				Sort:        "updated",
				Direction:   "desc",
				ListOptions: github.ListOptions{PerPage: 100},
			},
		}
	}

	var prPager *githubPRPager
	if needPRs {
		prPager = &githubPRPager{
			client: client,
			owner:  owner,
			repo:   repoName,
			opts: &github.PullRequestListOptions{
				State:       "all",
				Sort:        "updated",
				Direction:   "desc",
				ListOptions: github.ListOptions{PerPage: 100},
			},
		}
	}

	var (
		nextIssue *github.Issue
		nextPR    *github.PullRequest
		err       error
	)
	if issuePager != nil {
		nextIssue, err = issuePager.Next(ctx, s)
		if err != nil {
			return err
		}
	}
	if prPager != nil {
		nextPR, err = prPager.Next(ctx, s)
		if err != nil {
			return err
		}
	}

	count := 0
	issueCount := 0
	prCount := 0
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workerLimit)
	for nextIssue != nil || nextPR != nil {
		if s.IssueOpts.MaxIssues > 0 && count >= s.IssueOpts.MaxIssues {
			break
		}

		if nextPR != nil && (nextIssue == nil || nextPR.GetUpdatedAt().Time.After(nextIssue.GetUpdatedAt().Time)) {
			count++
			prCount++
			pr := nextPR
			g.Go(func() error {
				return s.scanPR(gctx, client, owner, repoName, pr, yield)
			})
			nextPR, err = prPager.Next(ctx, s)
			if err != nil {
				return err
			}
			continue
		}

		count++
		issueCount++
		issue := nextIssue
		g.Go(func() error {
			return s.scanIssue(gctx, client, owner, repoName, issue, yield)
		})
		nextIssue, err = issuePager.Next(ctx, s)
		if err != nil {
			return err
		}
	}

	if err := g.Wait(); err != nil {
		return err
	}

	logger.Debug().
		Int("workers", workerLimit).
		Int("items", count).
		Int("issues", issueCount).
		Int("prs", prCount).
		Dur("issues_prs_ms", time.Since(start)).
		Msg("issues/prs scan complete")

	return nil
}

func (s *GitHub) scanIssue(ctx context.Context, client *github.Client, owner, repoName string, issue *github.Issue, yield FragmentsFunc) error {
	if s.ScanIssues && (issue.GetTitle() != "" || issue.GetBody() != "") {
		frag := Fragment{Raw: strings.TrimSpace(issue.GetTitle() + "\n\n" + issue.GetBody())}
		frag.SetAttr(AttrPath, issue.GetHTMLURL())
		frag.SetAttr(AttrResource, ResourceGitHubIssue)
		frag.SetAttr(AttrGitHubIssueNumber, strconv.Itoa(issue.GetNumber()))

		if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
			if err := yield(frag, nil); err != nil {
				return err
			}
		}
	}

	if s.ScanComments && issue.GetComments() > 0 {
		if err := s.scanCommentsForIssue(ctx, client, owner, repoName, issue, yield); err != nil {
			logging.Warn().Err(err).Int("issue", issue.GetNumber()).Msg("could not scan comments")
		}
	}

	return nil
}

func (s *GitHub) scanPR(ctx context.Context, client *github.Client, owner, repoName string, pr *github.PullRequest, yield FragmentsFunc) error {
	if s.ScanPRs && (pr.GetTitle() != "" || pr.GetBody() != "") {
		frag := Fragment{Raw: strings.TrimSpace(pr.GetTitle() + "\n\n" + pr.GetBody())}
		frag.SetAttr(AttrPath, pr.GetHTMLURL())
		frag.SetAttr(AttrResource, ResourceGitHubPR)
		frag.SetAttr(AttrGitHubPRNumber, strconv.Itoa(pr.GetNumber()))

		if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
			if err := yield(frag, nil); err != nil {
				return err
			}
		}
	}

	if s.ScanComments {
		if err := s.scanCommentsForPR(ctx, client, owner, repoName, pr, yield); err != nil {
			logging.Warn().Err(err).Int("pr", pr.GetNumber()).Msg("could not scan pr comments")
		}
	}

	return nil
}

// scanCommentsForIssue scans issue comments for an issue or PR.
func (s *GitHub) scanCommentsForIssue(ctx context.Context, client *github.Client, owner, repoName string, issue *github.Issue, yield FragmentsFunc) error {
	start := time.Now()
	count := 0

	if err := s.scanIssueComments(ctx, client, owner, repoName, issue.GetNumber(), false, &count, yield); err != nil {
		return err
	}

	logging.Debug().
		Str("repo", owner+"/"+repoName).
		Int("issue", issue.GetNumber()).
		Int("comments", count).
		Dur("comments_ms", time.Since(start)).
		Msg("issue comments scan complete")

	return nil
}

func (s *GitHub) scanCommentsForPR(ctx context.Context, client *github.Client, owner, repoName string, pr *github.PullRequest, yield FragmentsFunc) error {
	start := time.Now()
	count := 0

	// Always attempt to fetch both issue-style and review comments.
	// The list endpoint metadata can undercount, so skipping based on the PR's
	// comment counters can miss real findings.
	if err := s.scanIssueComments(ctx, client, owner, repoName, pr.GetNumber(), true, &count, yield); err != nil {
		return err
	}

	if err := s.scanPRReviewComments(ctx, client, owner, repoName, pr.GetNumber(), &count, yield); err != nil {
		return err
	}

	logging.Debug().
		Str("repo", owner+"/"+repoName).
		Int("pr", pr.GetNumber()).
		Int("comments", count).
		Dur("comments_ms", time.Since(start)).
		Msg("pr comments scan complete")

	return nil
}

func (s *GitHub) scanIssueComments(ctx context.Context, client *github.Client, owner, repoName string, number int, isPR bool, count *int, yield FragmentsFunc) error {
	opts := &github.IssueListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	issueNumStr := strconv.Itoa(number)

	for {
		var comments []*github.IssueComment
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			comments, resp, err = client.Issues.ListComments(ctx, owner, repoName, number, opts)
			return err
		})
		if err != nil {
			return fmt.Errorf("list comments for #%d: %w", number, err)
		}

		for _, comment := range comments {
			if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
				return nil
			}

			if comment.GetBody() == "" {
				continue
			}
			*count = *count + 1

			frag := Fragment{Raw: comment.GetBody()}
			frag.SetAttr(AttrPath, comment.GetHTMLURL())
			frag.SetAttr(AttrResource, ResourceGitHubComment)
			frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(comment.GetID(), 10))

			if isPR {
				frag.SetAttr(AttrGitHubPRNumber, issueNumStr)
			} else {
				frag.SetAttr(AttrGitHubIssueNumber, issueNumStr)
			}
			if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
				if err := yield(frag, nil); err != nil {
					return err
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	return nil
}

func (s *GitHub) scanPRReviewComments(ctx context.Context, client *github.Client, owner, repoName string, number int, count *int, yield FragmentsFunc) error {
	opts := &github.PullRequestListCommentsOptions{
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	prNumStr := strconv.Itoa(number)

	for {
		var comments []*github.PullRequestComment
		var resp *github.Response
		err := s.withRetry(ctx, func() error {
			var err error
			comments, resp, err = client.PullRequests.ListComments(ctx, owner, repoName, number, opts)
			return err
		})
		if err != nil {
			return fmt.Errorf("list review comments for pr #%d: %w", number, err)
		}

		for _, comment := range comments {
			if s.IssueOpts.MaxComments > 0 && *count >= s.IssueOpts.MaxComments {
				return nil
			}

			if comment.GetBody() == "" {
				continue
			}
			*count = *count + 1

			frag := Fragment{Raw: comment.GetBody()}
			frag.SetAttr(AttrPath, comment.GetHTMLURL())
			frag.SetAttr(AttrResource, ResourceGitHubComment)
			frag.SetAttr(AttrGitHubCommentID, strconv.FormatInt(comment.GetID(), 10))
			frag.SetAttr(AttrGitHubPRNumber, prNumStr)

			if s.ShouldSkip == nil || !s.ShouldSkip(frag.Attributes) {
				if err := yield(frag, nil); err != nil {
					return err
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	return nil
}

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

// splitRepoSlug splits "owner/repo" into owner and repo.
func splitRepoSlug(slug string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("expected owner/repo format, got %q", slug)
	}
	return owner, repo, nil
}
