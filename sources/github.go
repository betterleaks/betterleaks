package sources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
			return s.scanRepo(gctx, repo, yield)
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

// scanRepo clones a single repo to a temp dir and delegates to the Git source.
func (s *GitHub) scanRepo(ctx context.Context, repo *github.Repository, yield FragmentsFunc) error {
	name := repo.GetFullName()
	logger := logging.With().Str("repo", name).Logger()
	logger.Info().Msg("scanning repo")

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
		logger.Error().Err(err).Msg("clone failed")
		return nil
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
			logger.Error().Err(err).Msg("could not create git log cmd")
			return nil
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
	scanErr := src.Fragments(ctx, func(fragment Fragment, err error) error {
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
	})
	logger.Debug().Msg("scan complete")
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

// splitRepoSlug splits "owner/repo" into owner and repo.
func splitRepoSlug(slug string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || repo == "" {
		return "", "", fmt.Errorf("expected owner/repo format, got %q", slug)
	}
	return owner, repo, nil
}
