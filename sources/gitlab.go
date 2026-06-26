package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/semgroup"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/internal/httpclient"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

const (
	gitlabPerPage         = 100
	gitlabScanConcurrency = 100
	gitlabAPIConcurrency  = 10
	gitlabDefaultBase     = "https://gitlab.com/"
	gitlabAPISuffix       = "api/v4/"
)

// GitLab enumerates projects via the GitLab REST API and delegates scanning
// to the Git source for each cloned repo.
type GitLab struct {
	// Auth
	Token string

	// Target URL (required). A gitlab.com or self-hosted instance URL pointing
	// at a project, group, user, or specific resource (issue, MR, snippet,
	// release, pipeline, job).
	URL string

	// BaseURL is the site base for self-hosted instances (e.g.
	// "https://gitlab.example.com/" or "https://corp.com/gitlab/"). Leave
	// empty to infer "<scheme>://<host>/" from URL.
	BaseURL string

	// Filtering
	ExcludeRepos []string // glob patterns matched against "group/sub/project"
	Include      []string
	Exclude      []string
	Resources    GitLabResourceSet

	// Group enumeration knobs
	AllGroups        bool
	IncludeSubgroups bool

	// Scan config (passed through to Git/ParallelGit per project)
	ShouldSkip      SkipFunc
	Sema            *semgroup.Group
	MaxArchiveDepth int
	Workers         int
	LogOpts         string

	// Date-range filtering for API-backed resources
	DateRangeOpts DateRangeOptions

	// Internal: lazily initialized in Fragments.
	httpClient *http.Client
	restRetry  *httpclient.RetryTransport
	apiBaseURL *url.URL // normalized site base ending in `/api/v4/`
	apiSem     chan struct{}
}

// GitLabResourceType identifies a scannable GitLab resource category.
type GitLabResourceType string

const (
	GitLabResourceTypeRepos         GitLabResourceType = "repos"
	GitLabResourceTypeForks         GitLabResourceType = "forks"
	GitLabResourceTypeMRs           GitLabResourceType = "mrs"
	GitLabResourceTypeMRComments    GitLabResourceType = "mr-comments"
	GitLabResourceTypeIssues        GitLabResourceType = "issues"
	GitLabResourceTypeIssueComments GitLabResourceType = "issue-comments"
	GitLabResourceTypeSnippets      GitLabResourceType = "snippets"
	GitLabResourceTypeReleases      GitLabResourceType = "releases"
	GitLabResourceTypeReleaseAssets GitLabResourceType = "release-assets"
	GitLabResourceTypeCIJobs        GitLabResourceType = "ci-jobs"
	GitLabResourceTypeCIArtifacts   GitLabResourceType = "ci-artifacts"
)

// AllGitLabResourceTypes is the canonical list of valid GitLab resource types.
var AllGitLabResourceTypes = []GitLabResourceType{
	GitLabResourceTypeRepos,
	GitLabResourceTypeForks,
	GitLabResourceTypeMRs,
	GitLabResourceTypeMRComments,
	GitLabResourceTypeIssues,
	GitLabResourceTypeIssueComments,
	GitLabResourceTypeSnippets,
	GitLabResourceTypeReleases,
	GitLabResourceTypeReleaseAssets,
	GitLabResourceTypeCIJobs,
	GitLabResourceTypeCIArtifacts,
}

// GitLabResourceSet tracks which resource types are enabled for scanning.
type GitLabResourceSet map[GitLabResourceType]bool

func (rs GitLabResourceSet) Has(r GitLabResourceType) bool { return rs[r] }

// HasAnyIssueOrMR reports whether any issue, MR, or comment resource is enabled.
func (rs GitLabResourceSet) HasAnyIssueOrMR() bool {
	return rs[GitLabResourceTypeIssues] || rs[GitLabResourceTypeMRs] ||
		rs[GitLabResourceTypeIssueComments] || rs[GitLabResourceTypeMRComments]
}

func (rs GitLabResourceSet) String() string {
	var out []string
	for rt := range rs {
		out = append(out, string(rt))
	}
	return strings.Join(out, ",")
}

// defaultGitLabScanResources lists the default resource types each URL kind scans.
var defaultGitLabScanResources = map[string][]GitLabResourceType{
	"namespace": {GitLabResourceTypeRepos},
	"project":   {GitLabResourceTypeRepos},
	"group":     {GitLabResourceTypeRepos},
	"user":      {GitLabResourceTypeRepos},
	"issue":     {GitLabResourceTypeIssues, GitLabResourceTypeIssueComments},
	"mr":        {GitLabResourceTypeMRs, GitLabResourceTypeMRComments},
	"snippet":   {GitLabResourceTypeSnippets},
	"release":   {GitLabResourceTypeReleases, GitLabResourceTypeReleaseAssets},
	"pipeline":  {GitLabResourceTypeCIJobs, GitLabResourceTypeCIArtifacts},
	"job":       {GitLabResourceTypeCIJobs, GitLabResourceTypeCIArtifacts},
}

// Validate checks the GitLab source configuration and populates Resources if needed.
func (s *GitLab) Validate() error {
	if s.URL == "" {
		return errors.New("target URL is required")
	}

	parsed, err := ParseGitLabURL(s.URL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	if s.BaseURL == "" {
		s.BaseURL = fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)
	}
	if !strings.HasSuffix(s.BaseURL, "/") {
		s.BaseURL += "/"
	}

	if len(s.Resources) == 0 {
		valid := make(map[GitLabResourceType]bool, len(AllGitLabResourceTypes))
		for _, rt := range AllGitLabResourceTypes {
			valid[rt] = true
		}
		rs := make(GitLabResourceSet)
		for _, rt := range defaultGitLabScanResources[parsed.Kind] {
			rs[rt] = true
		}
		for _, name := range s.Include {
			rt := GitLabResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			rs[rt] = true
		}
		excluded := make(map[GitLabResourceType]bool)
		for _, name := range s.Exclude {
			rt := GitLabResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			excluded[rt] = true
			delete(rs, rt)
		}
		if rs[GitLabResourceTypeReleases] && !excluded[GitLabResourceTypeReleaseAssets] {
			rs[GitLabResourceTypeReleaseAssets] = true
		}
		if rs[GitLabResourceTypeCIJobs] && !excluded[GitLabResourceTypeCIArtifacts] {
			rs[GitLabResourceTypeCIArtifacts] = true
		}
		s.Resources = rs
	}

	if s.Token == "" {
		if parsed.Kind == "namespace" || parsed.Kind == "group" || parsed.Kind == "user" {
			return errors.New("a token is required to enumerate group or user projects")
		}
		for rt := range s.Resources {
			if rt == GitLabResourceTypeRepos || rt == GitLabResourceTypeForks {
				continue
			}
			return fmt.Errorf("a token is required for API-based resources; only repos and forks can be scanned without a token")
		}
	}

	return nil
}

// Fragments enumerates GitLab projects and scans each one.
func (s *GitLab) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if err := s.Validate(); err != nil {
		return err
	}
	logging.Info().
		Str("target", s.URL).
		Str("base", s.BaseURL).
		Stringer("resources", s.Resources).
		Msg("starting GitLab scan")

	start := time.Now()
	if err := s.ensureClient(); err != nil {
		return err
	}

	target, direct, err := s.dispatchURL(ctx, s.URL)
	if err != nil {
		return err
	}

	if direct {
		return s.scanDirect(ctx, target, yield)
	}

	scanCtx, cancelScans := context.WithCancel(ctx)
	defer cancelScans()

	var scanGroup errgroup.Group
	scanGroup.SetLimit(gitlabScanConcurrency)

	projCh, enumErrCh := s.enumerateProjects(ctx, target)
	var projCount atomic.Int64
	for proj := range projCh {
		projCount.Add(1)
		scanGroup.Go(func() error {
			return s.scanProject(scanCtx, proj, yield)
		})
	}
	enumErr := <-enumErrCh
	if enumErr != nil {
		cancelScans()
		scanErr := scanGroup.Wait()
		combined := fmt.Errorf("enumerate projects: %w", enumErr)
		if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
			combined = errors.Join(combined, scanErr)
		}
		return combined
	}
	logging.Info().
		Int64("projects", projCount.Load()).
		Dur("enumeration_ms", time.Since(start)).
		Msg("enumeration complete, waiting for scans")

	scanErr := scanGroup.Wait()
	logging.Info().
		Int64("projects", projCount.Load()).
		Dur("duration", time.Since(start)).
		Msg("scan complete")
	return scanErr
}

// buildAPIBase normalizes BaseURL to an absolute URL ending in "/api/v4/".
func (s *GitLab) buildAPIBase() (*url.URL, error) {
	base := s.BaseURL
	if base == "" {
		base = gitlabDefaultBase
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid GitLab base URL %q: %w", base, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("GitLab base URL must include scheme and host: %q", base)
	}
	u.Path = singleSlashJoin(u.Path, gitlabAPISuffix)
	return u, nil
}

// apiURL returns an absolute URL for an API v4 endpoint relative to the
// configured base, e.g. apiURL("projects/123/issues") →
// "https://gitlab.com/api/v4/projects/123/issues".
func (s *GitLab) apiURL(endpoint string) (*url.URL, error) {
	if err := s.ensureClient(); err != nil {
		return nil, err
	}
	endpoint = strings.TrimPrefix(endpoint, "/")
	ref, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid GitLab endpoint %q: %w", endpoint, err)
	}
	return s.apiBaseURL.ResolveReference(ref), nil
}

func (s *GitLab) ensureClient() error {
	if s.restRetry == nil {
		s.restRetry = httpclient.NewRetryTransport(nil)
		s.restRetry.Decider = gitlabRetryDecider
		s.restRetry.StateExtractor = gitlabRateLimitStateExtractor
	}
	if s.apiBaseURL == nil {
		apiBase, err := s.buildAPIBase()
		if err != nil {
			return err
		}
		s.apiBaseURL = apiBase
	}
	if s.httpClient == nil {
		s.httpClient = httpclient.NewAuthenticatedClient(s.Token, s.restRetry, s.apiBaseURL.Host)
	}
	if s.apiSem == nil {
		s.apiSem = make(chan struct{}, gitlabAPIConcurrency)
	}
	return nil
}

func (s *GitLab) acquireAPISlot(ctx context.Context) (func(), error) {
	if s.apiSem == nil {
		return func() {}, nil
	}
	select {
	case s.apiSem <- struct{}{}:
		return func() { <-s.apiSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func singleSlashJoin(left, right string) string {
	if left == "" {
		left = "/"
	}
	if !strings.HasSuffix(left, "/") {
		left += "/"
	}
	right = strings.TrimPrefix(right, "/")
	return left + right
}

// ParsedGitLabURL is the result of splitting a GitLab URL into its components.
type ParsedGitLabURL struct {
	Scheme string // http or https
	Host   string // hostname[:port]
	Path   string // project/group/user path (everything before "/-/")
	Kind   string // "namespace", "project", "group", "user", "issue", "mr", "snippet", "release", "pipeline", "job"
	ID     string // resource ID (number, tag, snippet id)
}

// ParseGitLabURL parses a GitLab URL into namespace + optional resource segment.
// At this stage we cannot tell apart project / group / user — `dispatchURL`
// resolves that by querying the API.
func ParseGitLabURL(rawURL string) (*ParsedGitLabURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL must include a host")
	}

	out := &ParsedGitLabURL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}

	trimmed := strings.Trim(u.Path, "/")
	if trimmed == "" {
		// Bare host: only valid with explicit AllGroups; caller handles that
		// via the GitLab.AllGroups field. Kind = "namespace" with empty Path
		// signals "instance root".
		out.Kind = "namespace"
		return out, nil
	}

	left, right, hasResource := splitOnce(trimmed, "/-/")
	out.Path = strings.Trim(left, "/")
	if !hasResource {
		out.Kind = "namespace"
		return out, nil
	}

	parts := strings.Split(strings.Trim(right, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("GitLab resource URL must be .../-/{kind}/{id}")
	}
	kind, id := parts[0], parts[1]
	switch kind {
	case "issues":
		out.Kind = "issue"
		out.ID = id
	case "merge_requests":
		out.Kind = "mr"
		out.ID = id
	case "snippets":
		out.Kind = "snippet"
		out.ID = id
	case "releases":
		out.Kind = "release"
		out.ID = id
	case "pipelines":
		out.Kind = "pipeline"
		out.ID = id
	case "jobs":
		out.Kind = "job"
		out.ID = id
	default:
		return nil, fmt.Errorf("unsupported GitLab URL type %q; supported: issues, merge_requests, snippets, releases, pipelines, jobs", kind)
	}
	return out, nil
}

func splitOnce(s, sep string) (left, right string, ok bool) {
	return strings.Cut(s, sep)
}

// gitlabTarget describes what the URL resolved to: either a single project,
// or a namespace (group/user) to enumerate.
type gitlabTarget struct {
	Kind     string         // "project", "group", "user", "all-groups", "issue", "mr", "snippet", "release", "pipeline", "job"
	Project  *gitlabProject // populated when Kind in {project, issue, mr, snippet, release, pipeline, job}
	Group    *gitlabGroup
	User     *gitlabUser
	Resource ParsedGitLabURL // original parse result; preserves ID/Kind for direct resource scans
}

// dispatchURL resolves a raw GitLab URL into either a direct resource scan or
// a project-enumeration target. For namespace URLs, it probes the API to
// determine whether the path is a project, group, or user.
func (s *GitLab) dispatchURL(ctx context.Context, rawURL string) (*gitlabTarget, bool, error) {
	parsed, err := ParseGitLabURL(rawURL)
	if err != nil {
		return nil, false, fmt.Errorf("invalid target URL: %w", err)
	}

	// Specific resource URL: project path lives in parsed.Path; fetch the
	// project, then return Direct=true so scanDirect handles just this resource.
	switch parsed.Kind {
	case "issue", "mr", "snippet", "release", "pipeline", "job":
		proj, err := s.fetchProjectByPath(ctx, parsed.Path)
		if err != nil {
			return nil, false, fmt.Errorf("fetch project %q: %w", parsed.Path, err)
		}
		return &gitlabTarget{Kind: parsed.Kind, Project: proj, Resource: *parsed}, true, nil
	}

	// Namespace URL with empty path = instance root → enumerate all groups
	// (only meaningful when AllGroups is set; otherwise it's an error).
	if parsed.Path == "" {
		if !s.AllGroups {
			return nil, false, errors.New("URL points at the GitLab instance root; set --all-groups to enumerate all visible groups")
		}
		return &gitlabTarget{Kind: "all-groups"}, false, nil
	}

	// Try project first, then group, then user.
	if proj, err := s.fetchProjectByPath(ctx, parsed.Path); err == nil {
		return &gitlabTarget{Kind: "project", Project: proj}, false, nil
	} else if !isGitLabStatusErr(err, http.StatusNotFound, http.StatusForbidden) {
		return nil, false, fmt.Errorf("probe project %q: %w", parsed.Path, err)
	}
	if grp, err := s.fetchGroupByPath(ctx, parsed.Path); err == nil {
		return &gitlabTarget{Kind: "group", Group: grp}, false, nil
	} else if !isGitLabStatusErr(err, http.StatusNotFound, http.StatusForbidden) {
		return nil, false, fmt.Errorf("probe group %q: %w", parsed.Path, err)
	}
	if !strings.Contains(parsed.Path, "/") {
		if usr, err := s.fetchUserByUsername(ctx, parsed.Path); err == nil && usr != nil {
			return &gitlabTarget{Kind: "user", User: usr}, false, nil
		}
	}
	return nil, false, fmt.Errorf("could not resolve %q as a GitLab project, group, or user", parsed.Path)
}

type gitlabProject struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	Path              string `json:"path"`
	PathWithNamespace string `json:"path_with_namespace"`
	Visibility        string `json:"visibility"`
	WebURL            string `json:"web_url"`
	HTTPURLToRepo     string `json:"http_url_to_repo"`
	DefaultBranch     string `json:"default_branch"`
	Namespace         struct {
		Path     string `json:"path"`
		FullPath string `json:"full_path"`
		Kind     string `json:"kind"`
	} `json:"namespace"`
	ForkedFromProject *struct {
		ID int `json:"id"`
	} `json:"forked_from_project,omitempty"`
}

func (p *gitlabProject) IsFork() bool { return p != nil && p.ForkedFromProject != nil }

type gitlabGroup struct {
	ID       int    `json:"id"`
	FullPath string `json:"full_path"`
	WebURL   string `json:"web_url"`
}

type gitlabUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	WebURL   string `json:"web_url"`
}

type gitlabAuthor struct {
	Name     string `json:"name"`
	Username string `json:"username"`
}

type gitlabIssue struct {
	IID         int          `json:"iid"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	WebURL      string       `json:"web_url"`
	CreatedAt   time.Time    `json:"created_at"`
	Author      gitlabAuthor `json:"author"`
}

type gitlabMR struct {
	IID         int          `json:"iid"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	WebURL      string       `json:"web_url"`
	CreatedAt   time.Time    `json:"created_at"`
	Author      gitlabAuthor `json:"author"`
}

type gitlabNote struct {
	ID        int64        `json:"id"`
	Body      string       `json:"body"`
	CreatedAt time.Time    `json:"created_at"`
	Author    gitlabAuthor `json:"author"`
	System    bool         `json:"system"`
}

type gitlabSnippet struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	FileName string `json:"file_name"`
	WebURL   string `json:"web_url"`
	RawURL   string `json:"raw_url"`
}

type gitlabReleaseAssetLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type gitlabReleaseAssetSource struct {
	Format string `json:"format"`
	URL    string `json:"url"`
}

type gitlabRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	ReleasedAt  time.Time `json:"released_at"`
	Assets      struct {
		Sources []gitlabReleaseAssetSource `json:"sources"`
		Links   []gitlabReleaseAssetLink   `json:"links"`
	} `json:"assets"`
}

type gitlabJob struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Stage      string    `json:"stage"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at"`
	Pipeline   struct {
		ID int64 `json:"id"`
	} `json:"pipeline"`
	WebURL    string `json:"web_url"`
	Artifacts []struct {
		FileType string `json:"file_type"`
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
	} `json:"artifacts"`
}

// doJSON issues a GET against the GitLab API and decodes the body into out.
// Returns a *gitlabStatusError on non-2xx so callers can inspect status codes.
func (s *GitLab) doJSON(ctx context.Context, u *url.URL, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	release, err := s.acquireAPISlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &gitlabStatusError{Status: resp.StatusCode, URL: u.String(), Body: string(body)}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// paginateJSON fetches a paged endpoint, calling collect once per page until
// the server stops returning a next-page header. base may already contain
// query parameters; per_page and page are appended.
func (s *GitLab) paginateJSON(ctx context.Context, base *url.URL, collect func(body []byte) (more bool, err error)) error {
	page := 1
	for {
		u := withQuery(base, "per_page", strconv.Itoa(gitlabPerPage), "page", strconv.Itoa(page))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		release, err := s.acquireAPISlot(ctx)
		if err != nil {
			return err
		}
		resp, err := s.httpClient.Do(req)
		release()
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &gitlabStatusError{Status: resp.StatusCode, URL: u.String(), Body: string(body)}
		}
		more, err := collect(body)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
		next := resp.Header.Get("X-Next-Page")
		if next == "" || next == "0" {
			return nil
		}
		nextPage, err := strconv.Atoi(next)
		if err != nil || nextPage <= page {
			return nil
		}
		page = nextPage
	}
}

func withQuery(base *url.URL, kv ...string) *url.URL {
	out := *base
	q := out.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	out.RawQuery = q.Encode()
	return &out
}

type gitlabStatusError struct {
	Status int
	URL    string
	Body   string
}

func (e *gitlabStatusError) Error() string {
	return fmt.Sprintf("GitLab API %s: HTTP %d: %s", e.URL, e.Status, strings.TrimSpace(e.Body))
}

func isGitLabStatusErr(err error, codes ...int) bool {
	var ge *gitlabStatusError
	if !errors.As(err, &ge) {
		return false
	}
	return slices.Contains(codes, ge.Status)
}

func (s *GitLab) fetchProjectByPath(ctx context.Context, projectPath string) (*gitlabProject, error) {
	encoded := url.PathEscape(projectPath)
	u, err := s.apiURL("projects/" + encoded)
	if err != nil {
		return nil, err
	}
	var proj gitlabProject
	if err := s.doJSON(ctx, u, &proj); err != nil {
		return nil, err
	}
	return &proj, nil
}

func (s *GitLab) fetchGroupByPath(ctx context.Context, groupPath string) (*gitlabGroup, error) {
	encoded := url.PathEscape(groupPath)
	u, err := s.apiURL("groups/" + encoded)
	if err != nil {
		return nil, err
	}
	var grp gitlabGroup
	if err := s.doJSON(ctx, u, &grp); err != nil {
		return nil, err
	}
	return &grp, nil
}

func (s *GitLab) fetchUserByUsername(ctx context.Context, username string) (*gitlabUser, error) {
	u, err := s.apiURL("users")
	if err != nil {
		return nil, err
	}
	u = withQuery(u, "username", username)
	var users []gitlabUser
	if err := s.doJSON(ctx, u, &users); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	return &users[0], nil
}

func (s *GitLab) enumerateProjects(ctx context.Context, target *gitlabTarget) (<-chan *gitlabProject, <-chan error) {
	ch := make(chan *gitlabProject, 100)
	errCh := make(chan error, 1)

	go func() {
		defer close(ch)
		defer close(errCh)

		seen := make(map[int]bool)
		send := func(p *gitlabProject) {
			if p == nil || seen[p.ID] {
				return
			}
			if !s.Resources.Has(GitLabResourceTypeForks) && p.IsFork() {
				return
			}
			if s.isExcluded(p.PathWithNamespace) {
				logging.Debug().Str("project", p.PathWithNamespace).Msg("excluding project")
				return
			}
			seen[p.ID] = true
			select {
			case ch <- p:
			case <-ctx.Done():
			}
		}

		switch target.Kind {
		case "project":
			send(target.Project)
		case "group":
			if err := s.streamGroupProjects(ctx, target.Group.ID, send); err != nil {
				errCh <- fmt.Errorf("list group %d projects: %w", target.Group.ID, err)
				return
			}
		case "user":
			if err := s.streamUserProjects(ctx, target.User.ID, send); err != nil {
				errCh <- fmt.Errorf("list user %d projects: %w", target.User.ID, err)
				return
			}
		case "all-groups":
			groups, err := s.listAllGroups(ctx)
			if err != nil {
				errCh <- fmt.Errorf("list all groups: %w", err)
				return
			}
			for _, g := range groups {
				if err := s.streamGroupProjects(ctx, g.ID, send); err != nil {
					errCh <- fmt.Errorf("list group %d projects: %w", g.ID, err)
					return
				}
			}
		default:
			errCh <- fmt.Errorf("unsupported enumeration target %q", target.Kind)
		}
	}()

	return ch, errCh
}

func (s *GitLab) streamGroupProjects(ctx context.Context, groupID int, send func(*gitlabProject)) error {
	u, err := s.apiURL(fmt.Sprintf("groups/%d/projects", groupID))
	if err != nil {
		return err
	}
	if s.IncludeSubgroups {
		u = withQuery(u, "include_subgroups", "true")
	}
	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var projects []gitlabProject
		if err := json.Unmarshal(body, &projects); err != nil {
			return false, fmt.Errorf("decode group projects: %w", err)
		}
		for i := range projects {
			send(&projects[i])
		}
		return len(projects) == gitlabPerPage, nil
	})
}

func (s *GitLab) streamUserProjects(ctx context.Context, userID int, send func(*gitlabProject)) error {
	u, err := s.apiURL(fmt.Sprintf("users/%d/projects", userID))
	if err != nil {
		return err
	}
	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var projects []gitlabProject
		if err := json.Unmarshal(body, &projects); err != nil {
			return false, fmt.Errorf("decode user projects: %w", err)
		}
		for i := range projects {
			send(&projects[i])
		}
		return len(projects) == gitlabPerPage, nil
	})
}

func (s *GitLab) listAllGroups(ctx context.Context) ([]gitlabGroup, error) {
	u, err := s.apiURL("groups")
	if err != nil {
		return nil, err
	}
	u = withQuery(u, "all_available", "true")
	var all []gitlabGroup
	err = s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabGroup
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode groups: %w", err)
		}
		all = append(all, page...)
		return len(page) == gitlabPerPage, nil
	})
	return all, err
}

// isExcluded matches a project's full path against the user-configured glob
// list, case-folded for predictability.
func (s *GitLab) isExcluded(fullPath string) bool {
	lp := strings.ToLower(fullPath)
	for _, pattern := range s.ExcludeRepos {
		if matched, _ := filepath.Match(strings.ToLower(pattern), lp); matched {
			return true
		}
	}
	return false
}

// projectAttributes builds the L1 attribute set for a project. When resource
// is non-empty it is stamped as AttrResource — used to distinguish the early
// "skip this whole project" check from the per-fragment attribute stamp.
func (s *GitLab) projectAttributes(proj *gitlabProject, resource string) map[string]string {
	attrs := map[string]string{
		AttrGitLabProjectID:   strconv.Itoa(proj.ID),
		AttrGitLabProjectPath: proj.PathWithNamespace,
		AttrGitLabProjectURL:  proj.WebURL,
		AttrGitLabVisibility:  proj.Visibility,
		AttrGitLabNamespace:   proj.Namespace.FullPath,
	}
	if resource != "" {
		attrs[AttrResource] = resource
	}
	return attrs
}

// wrapGitLabYield stamps project-level attributes onto every fragment and
// applies ShouldSkip as a final per-fragment filter (L3). Callers must use
// the returned yield in place of the original.
func wrapGitLabYield(skip SkipFunc, attrs map[string]string, yield FragmentsFunc) FragmentsFunc {
	var mu sync.Mutex
	return func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range attrs {
				if v == "" || fragment.Attr(k) != "" {
					continue
				}
				fragment.SetAttr(k, v)
			}
			if skip != nil && skip(fragment.Attributes) {
				return nil
			}
		}
		mu.Lock()
		defer mu.Unlock()
		return yield(fragment, err)
	}
}

// inDateRange mirrors GitHub.inDateRange for use in API listings ordered DESC
// by created_at. Returns (ok, terminate) where terminate=true means we can
// stop pagination because subsequent items will all be older than Since.
func (s *GitLab) inDateRange(t time.Time) (ok bool, terminate bool) {
	if !s.DateRangeOpts.Since.IsZero() && t.Before(s.DateRangeOpts.Since) {
		return false, true
	}
	if !s.DateRangeOpts.Until.IsZero() && !t.Before(s.DateRangeOpts.Until) {
		return false, false
	}
	return true, false
}

// scanProject is the main dispatch for one project. It implements the L1 +
// L3 skip layers and delegates to per-resource scanners which add their own
// L2 skips.
func (s *GitLab) scanProject(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	logger := logging.With().Str("project", proj.PathWithNamespace).Logger()
	projectAttrs := s.projectAttributes(proj, "")

	// L1 — drop the whole project early.
	if s.ShouldSkip != nil && s.ShouldSkip(s.projectAttributes(proj, ResourceGitLabProject)) {
		logger.Debug().Msg("skipping project based on prefilter")
		return nil
	}

	// L3 — every fragment from this project gets project attrs + per-fragment skip.
	glYield := wrapGitLabYield(s.ShouldSkip, projectAttrs, yield)

	run := func(label string, fn func() error) error {
		logger.Info().Str("resource", label).Msg("scanning")
		if err := fn(); err != nil {
			logger.Error().Err(err).Msg(label + " scan failed")
			return err
		}
		ev := logger.Info().Str("resource", label)
		if r := s.rateLimitRemaining(); r > 0 {
			ev = ev.Int64("rl_remaining", r)
		}
		ev.Msg("completed")
		return nil
	}

	if s.Resources.Has(GitLabResourceTypeRepos) {
		if err := run("repos", func() error { return s.scanProjectGit(ctx, proj, glYield) }); err != nil {
			return err
		}
	}
	if s.Resources.HasAnyIssueOrMR() {
		if err := run("issues_mrs", func() error { return s.scanIssuesAndMRs(ctx, proj, glYield) }); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitLabResourceTypeSnippets) {
		if err := run("snippets", func() error { return s.scanSnippets(ctx, proj, glYield) }); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitLabResourceTypeReleases) {
		if err := run("releases", func() error { return s.scanReleases(ctx, proj, glYield) }); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitLabResourceTypeCIJobs) {
		if err := run("ci_jobs", func() error { return s.scanCIJobs(ctx, proj, glYield) }); err != nil {
			return err
		}
	}
	return nil
}

// scanProjectGit clones the project and scans its git history.
func (s *GitLab) scanProjectGit(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	if proj.HTTPURLToRepo == "" {
		return nil
	}
	return scm.CloneToTempDir(ctx, proj.HTTPURLToRepo, s.Token, "betterleaks-gitlab-*", scm.CloneOptions{Mirror: true}, func(repoPath string) error {
		var src Source
		if s.Workers > 0 {
			src = &ParallelGit{
				RepoPath: repoPath, ShouldSkip: s.ShouldSkip,
				Platform: scm.GitLabPlatform, RemoteURL: proj.WebURL,
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
				Platform: scm.GitLabPlatform, RemoteURL: proj.WebURL,
				Sema: s.Sema, MaxArchiveDepth: s.MaxArchiveDepth,
			}
		}
		return src.Fragments(ctx, yield)
	})
}

func (s *GitLab) scanIssuesAndMRs(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	if s.Resources.Has(GitLabResourceTypeIssues) || s.Resources.Has(GitLabResourceTypeIssueComments) {
		if err := s.scanIssues(ctx, proj, yield); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitLabResourceTypeMRs) || s.Resources.Has(GitLabResourceTypeMRComments) {
		if err := s.scanMRs(ctx, proj, yield); err != nil {
			return err
		}
	}
	return nil
}

func (s *GitLab) scanIssues(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/issues", proj.ID))
	if err != nil {
		return err
	}
	u = withQuery(u, "scope", "all", "state", "all", "order_by", "created_at", "sort", "desc")
	u = s.applyDateRange(u, "created_after", "created_before")

	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabIssue
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode issues: %w", err)
		}
		for _, issue := range page {
			if ok, stop := s.inDateRange(issue.CreatedAt); stop {
				return false, nil
			} else if !ok {
				continue
			}
			attrs := map[string]string{
				AttrResource:       ResourceGitLabIssue,
				AttrGitLabIssueIID: strconv.Itoa(issue.IID),
				AttrURL:            issue.WebURL,
			}
			// L2 skip: drop this whole issue (body + comments) without fetching notes.
			if shouldSkipAttrs(s.ShouldSkip, attrs) {
				continue
			}
			if s.Resources.Has(GitLabResourceTypeIssues) {
				frag := Fragment{Raw: strings.TrimSpace(issue.Title + "\n" + issue.Description), Attributes: cloneAttrs(attrs)}
				if err := yield(frag, nil); err != nil {
					return false, err
				}
			}
			if s.Resources.Has(GitLabResourceTypeIssueComments) {
				if err := s.scanItemNotes(ctx, proj.ID, "issues", issue.IID, issue.WebURL, AttrGitLabIssueIID, strconv.Itoa(issue.IID), yield); err != nil {
					return false, err
				}
			}
		}
		return len(page) == gitlabPerPage, nil
	})
}

func (s *GitLab) scanMRs(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/merge_requests", proj.ID))
	if err != nil {
		return err
	}
	u = withQuery(u, "scope", "all", "state", "all", "order_by", "created_at", "sort", "desc")
	u = s.applyDateRange(u, "created_after", "created_before")

	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabMR
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode merge requests: %w", err)
		}
		for _, mr := range page {
			if ok, stop := s.inDateRange(mr.CreatedAt); stop {
				return false, nil
			} else if !ok {
				continue
			}
			attrs := map[string]string{
				AttrResource:    ResourceGitLabMR,
				AttrGitLabMRIID: strconv.Itoa(mr.IID),
				AttrURL:         mr.WebURL,
			}
			if shouldSkipAttrs(s.ShouldSkip, attrs) {
				continue
			}
			if s.Resources.Has(GitLabResourceTypeMRs) {
				frag := Fragment{Raw: strings.TrimSpace(mr.Title + "\n" + mr.Description), Attributes: cloneAttrs(attrs)}
				if err := yield(frag, nil); err != nil {
					return false, err
				}
			}
			if s.Resources.Has(GitLabResourceTypeMRComments) {
				if err := s.scanItemNotes(ctx, proj.ID, "merge_requests", mr.IID, mr.WebURL, AttrGitLabMRIID, strconv.Itoa(mr.IID), yield); err != nil {
					return false, err
				}
			}
		}
		return len(page) == gitlabPerPage, nil
	})
}

// scanItemNotes paginates notes (comments) for an issue or MR.
// itemKind is "issues" or "merge_requests"; parentAttrKey/Val identifies the
// parent (e.g. AttrGitLabMRIID + the IID).
func (s *GitLab) scanItemNotes(ctx context.Context, projectID int, itemKind string, itemIID int, parentURL, parentAttrKey, parentAttrVal string, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/%s/%d/notes", projectID, itemKind, itemIID))
	if err != nil {
		return err
	}
	u = withQuery(u, "order_by", "created_at", "sort", "asc")
	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabNote
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode notes: %w", err)
		}
		for _, note := range page {
			if note.System {
				continue // skip "merged", "assigned", and other system notes
			}
			attrs := map[string]string{
				AttrResource:        ResourceGitLabComment,
				AttrGitLabCommentID: strconv.FormatInt(note.ID, 10),
				AttrURL:             gitlabNoteURL(parentURL, note.ID),
				parentAttrKey:       parentAttrVal,
			}
			if shouldSkipAttrs(s.ShouldSkip, attrs) {
				continue
			}
			frag := Fragment{Raw: note.Body, Attributes: cloneAttrs(attrs)}
			if err := yield(frag, nil); err != nil {
				return false, err
			}
		}
		return len(page) == gitlabPerPage, nil
	})
}

func (s *GitLab) scanSnippets(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/snippets", proj.ID))
	if err != nil {
		return err
	}
	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabSnippet
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode snippets: %w", err)
		}
		for _, snip := range page {
			attrs := map[string]string{
				AttrResource:              ResourceGitLabSnippet,
				AttrGitLabSnippetID:       strconv.FormatInt(snip.ID, 10),
				AttrGitLabSnippetFilename: snip.FileName,
				AttrURL:                   snip.WebURL,
				AttrPath:                  snip.FileName,
			}
			if shouldSkipAttrs(s.ShouldSkip, attrs) {
				continue
			}
			raw, err := s.apiURL(fmt.Sprintf("projects/%d/snippets/%d/raw", proj.ID, snip.ID))
			if err != nil {
				return false, err
			}
			if err := s.downloadAndScan(ctx, raw.String(), snip.FileName, attrs, yield); err != nil {
				logging.Error().Err(err).Str("snippet", snip.FileName).Msg("could not scan snippet")
			}
		}
		return len(page) == gitlabPerPage, nil
	})
}

func (s *GitLab) scanReleases(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/releases", proj.ID))
	if err != nil {
		return err
	}
	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabRelease
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode releases: %w", err)
		}
		for _, rel := range page {
			if ok, stop := s.inDateRange(timeOr(rel.ReleasedAt, rel.CreatedAt)); stop {
				return false, nil
			} else if !ok {
				continue
			}
			attrs := map[string]string{
				AttrResource:         ResourceGitLabRelease,
				AttrGitLabReleaseTag: rel.TagName,
			}
			if shouldSkipAttrs(s.ShouldSkip, attrs) {
				continue
			}
			if rel.Description != "" {
				frag := Fragment{Raw: rel.Description, Attributes: cloneAttrs(attrs)}
				if err := yield(frag, nil); err != nil {
					return false, err
				}
			}
			if err := s.scanReleaseAssets(ctx, rel, yield); err != nil {
				return false, err
			}
		}
		return len(page) == gitlabPerPage, nil
	})
}

func (s *GitLab) scanCIJobs(ctx context.Context, proj *gitlabProject, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/jobs", proj.ID))
	if err != nil {
		return err
	}
	return s.scanCIJobsURL(ctx, proj, u, yield)
}

func (s *GitLab) scanPipelineJobs(ctx context.Context, proj *gitlabProject, pipelineID int64, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/pipelines/%d/jobs", proj.ID, pipelineID))
	if err != nil {
		return err
	}
	return s.scanCIJobsURL(ctx, proj, u, yield)
}

func (s *GitLab) scanSingleCIJob(ctx context.Context, proj *gitlabProject, jobID int64, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/jobs/%d", proj.ID, jobID))
	if err != nil {
		return err
	}
	var job gitlabJob
	if err := s.doJSON(ctx, u, &job); err != nil {
		return err
	}
	ok, _ := s.inDateRange(job.CreatedAt)
	if !ok {
		return nil
	}
	return s.scanCIJob(ctx, proj, job, yield)
}

func (s *GitLab) scanCIJobsURL(ctx context.Context, proj *gitlabProject, u *url.URL, yield FragmentsFunc) error {
	return s.paginateJSON(ctx, u, func(body []byte) (bool, error) {
		var page []gitlabJob
		if err := json.Unmarshal(body, &page); err != nil {
			return false, fmt.Errorf("decode jobs: %w", err)
		}
		for _, job := range page {
			if ok, stop := s.inDateRange(job.CreatedAt); stop {
				return false, nil
			} else if !ok {
				continue
			}
			if err := s.scanCIJob(ctx, proj, job, yield); err != nil {
				return false, err
			}
		}
		return len(page) == gitlabPerPage, nil
	})
}

func (s *GitLab) scanCIJob(ctx context.Context, proj *gitlabProject, job gitlabJob, yield FragmentsFunc) error {
	attrs := map[string]string{
		AttrResource:           ResourceGitLabCIJob,
		AttrGitLabCIJobID:      strconv.FormatInt(job.ID, 10),
		AttrGitLabCIJobName:    job.Name,
		AttrGitLabCIPipelineID: strconv.FormatInt(job.Pipeline.ID, 10),
		AttrURL:                job.WebURL,
	}
	if shouldSkipAttrs(s.ShouldSkip, attrs) {
		return nil
	}
	traceURL, err := s.apiURL(fmt.Sprintf("projects/%d/jobs/%d/trace", proj.ID, job.ID))
	if err != nil {
		return err
	}
	logPath := fmt.Sprintf("ci/jobs/%s/job_%d.log", safePath(job.Name), job.ID)
	if err := s.downloadAndScan(ctx, traceURL.String(), logPath, attrs, yield); err != nil {
		logging.Debug().Err(err).Int64("job", job.ID).Msg("could not scan job trace")
	}
	if !s.Resources.Has(GitLabResourceTypeCIArtifacts) || len(job.Artifacts) == 0 {
		return nil
	}
	artifactAttrs := map[string]string{
		AttrResource:           ResourceGitLabCIArtifact,
		AttrGitLabCIJobID:      strconv.FormatInt(job.ID, 10),
		AttrGitLabCIJobName:    job.Name,
		AttrGitLabCIPipelineID: strconv.FormatInt(job.Pipeline.ID, 10),
		AttrURL:                job.WebURL,
	}
	if shouldSkipAttrs(s.ShouldSkip, artifactAttrs) {
		return nil
	}
	artURL, err := s.apiURL(fmt.Sprintf("projects/%d/jobs/%d/artifacts", proj.ID, job.ID))
	if err != nil {
		return err
	}
	artifactPath := fmt.Sprintf("ci/artifacts/%s/job_%d.zip", safePath(job.Name), job.ID)
	if err := s.downloadAndScan(ctx, artURL.String(), artifactPath, artifactAttrs, yield); err != nil {
		logging.Debug().Err(err).Int64("job", job.ID).Msg("could not scan job artifacts")
	}
	return nil
}

func (s *GitLab) scanDirect(ctx context.Context, target *gitlabTarget, yield FragmentsFunc) error {
	if target.Project == nil {
		return fmt.Errorf("direct scan requires a resolved project")
	}
	projectAttrs := s.projectAttributes(target.Project, "")
	if s.ShouldSkip != nil && s.ShouldSkip(s.projectAttributes(target.Project, ResourceGitLabProject)) {
		return nil
	}
	glYield := wrapGitLabYield(s.ShouldSkip, projectAttrs, yield)

	switch target.Kind {
	case "issue":
		iid, err := strconv.Atoi(target.Resource.ID)
		if err != nil {
			return fmt.Errorf("invalid issue iid %q", target.Resource.ID)
		}
		return s.scanSingleIssue(ctx, target.Project, iid, glYield)
	case "mr":
		iid, err := strconv.Atoi(target.Resource.ID)
		if err != nil {
			return fmt.Errorf("invalid mr iid %q", target.Resource.ID)
		}
		return s.scanSingleMR(ctx, target.Project, iid, glYield)
	case "snippet":
		sid, err := strconv.ParseInt(target.Resource.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid snippet id %q", target.Resource.ID)
		}
		return s.scanSingleSnippet(ctx, target.Project, sid, glYield)
	case "release":
		return s.scanSingleRelease(ctx, target.Project, target.Resource.ID, glYield)
	case "pipeline":
		pipelineID, err := strconv.ParseInt(target.Resource.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid pipeline id %q", target.Resource.ID)
		}
		return s.scanPipelineJobs(ctx, target.Project, pipelineID, glYield)
	case "job":
		jobID, err := strconv.ParseInt(target.Resource.ID, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid job id %q", target.Resource.ID)
		}
		return s.scanSingleCIJob(ctx, target.Project, jobID, glYield)
	default:
		return fmt.Errorf("unsupported direct resource %q", target.Kind)
	}
}

func (s *GitLab) scanSingleIssue(ctx context.Context, proj *gitlabProject, iid int, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/issues/%d", proj.ID, iid))
	if err != nil {
		return err
	}
	var issue gitlabIssue
	if err := s.doJSON(ctx, u, &issue); err != nil {
		return err
	}
	attrs := map[string]string{
		AttrResource:       ResourceGitLabIssue,
		AttrGitLabIssueIID: strconv.Itoa(issue.IID),
		AttrURL:            issue.WebURL,
	}
	if shouldSkipAttrs(s.ShouldSkip, attrs) {
		return nil
	}
	if s.Resources.Has(GitLabResourceTypeIssues) {
		frag := Fragment{Raw: strings.TrimSpace(issue.Title + "\n" + issue.Description), Attributes: cloneAttrs(attrs)}
		if err := yield(frag, nil); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitLabResourceTypeIssueComments) {
		return s.scanItemNotes(ctx, proj.ID, "issues", issue.IID, issue.WebURL, AttrGitLabIssueIID, strconv.Itoa(issue.IID), yield)
	}
	return nil
}

func (s *GitLab) scanSingleMR(ctx context.Context, proj *gitlabProject, iid int, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/merge_requests/%d", proj.ID, iid))
	if err != nil {
		return err
	}
	var mr gitlabMR
	if err := s.doJSON(ctx, u, &mr); err != nil {
		return err
	}
	attrs := map[string]string{
		AttrResource:    ResourceGitLabMR,
		AttrGitLabMRIID: strconv.Itoa(mr.IID),
		AttrURL:         mr.WebURL,
	}
	if shouldSkipAttrs(s.ShouldSkip, attrs) {
		return nil
	}
	if s.Resources.Has(GitLabResourceTypeMRs) {
		frag := Fragment{Raw: strings.TrimSpace(mr.Title + "\n" + mr.Description), Attributes: cloneAttrs(attrs)}
		if err := yield(frag, nil); err != nil {
			return err
		}
	}
	if s.Resources.Has(GitLabResourceTypeMRComments) {
		return s.scanItemNotes(ctx, proj.ID, "merge_requests", mr.IID, mr.WebURL, AttrGitLabMRIID, strconv.Itoa(mr.IID), yield)
	}
	return nil
}

func (s *GitLab) scanSingleSnippet(ctx context.Context, proj *gitlabProject, snippetID int64, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/snippets/%d", proj.ID, snippetID))
	if err != nil {
		return err
	}
	var snip gitlabSnippet
	if err := s.doJSON(ctx, u, &snip); err != nil {
		return err
	}
	attrs := map[string]string{
		AttrResource:              ResourceGitLabSnippet,
		AttrGitLabSnippetID:       strconv.FormatInt(snip.ID, 10),
		AttrGitLabSnippetFilename: snip.FileName,
		AttrURL:                   snip.WebURL,
		AttrPath:                  snip.FileName,
	}
	if shouldSkipAttrs(s.ShouldSkip, attrs) {
		return nil
	}
	raw, err := s.apiURL(fmt.Sprintf("projects/%d/snippets/%d/raw", proj.ID, snip.ID))
	if err != nil {
		return err
	}
	return s.downloadAndScan(ctx, raw.String(), snip.FileName, attrs, yield)
}

func (s *GitLab) scanSingleRelease(ctx context.Context, proj *gitlabProject, tag string, yield FragmentsFunc) error {
	u, err := s.apiURL(fmt.Sprintf("projects/%d/releases/%s", proj.ID, url.PathEscape(tag)))
	if err != nil {
		return err
	}
	var rel gitlabRelease
	if err := s.doJSON(ctx, u, &rel); err != nil {
		return err
	}
	attrs := map[string]string{
		AttrResource:         ResourceGitLabRelease,
		AttrGitLabReleaseTag: rel.TagName,
	}
	if shouldSkipAttrs(s.ShouldSkip, attrs) {
		return nil
	}
	if rel.Description != "" && s.Resources.Has(GitLabResourceTypeReleases) {
		frag := Fragment{Raw: rel.Description, Attributes: cloneAttrs(attrs)}
		if err := yield(frag, nil); err != nil {
			return err
		}
	}
	if !s.Resources.Has(GitLabResourceTypeReleaseAssets) {
		return nil
	}
	return s.scanReleaseAssets(ctx, rel, yield)
}

func (s *GitLab) scanReleaseAssets(ctx context.Context, rel gitlabRelease, yield FragmentsFunc) error {
	if !s.Resources.Has(GitLabResourceTypeReleaseAssets) {
		return nil
	}
	for _, src := range rel.Assets.Sources {
		if src.URL == "" {
			continue
		}
		name := "source." + src.Format
		assetAttrs := map[string]string{
			AttrResource:               ResourceGitLabReleaseAsset,
			AttrGitLabReleaseTag:       rel.TagName,
			AttrGitLabReleaseAssetName: name,
		}
		if shouldSkipAttrs(s.ShouldSkip, assetAttrs) {
			continue
		}
		if err := s.downloadAndScan(ctx, src.URL, "release/"+rel.TagName+"/"+name, assetAttrs, yield); err != nil {
			logging.Error().Err(err).Str("tag", rel.TagName).Str("asset", name).Msg("could not scan release source archive")
		}
	}
	for _, link := range rel.Assets.Links {
		if link.URL == "" {
			continue
		}
		assetAttrs := map[string]string{
			AttrResource:               ResourceGitLabReleaseAsset,
			AttrGitLabReleaseTag:       rel.TagName,
			AttrGitLabReleaseAssetName: link.Name,
		}
		if shouldSkipAttrs(s.ShouldSkip, assetAttrs) {
			continue
		}
		if err := s.downloadAndScan(ctx, link.URL, "release/"+rel.TagName+"/"+link.Name, assetAttrs, yield); err != nil {
			logging.Error().Err(err).Str("tag", rel.TagName).Str("asset", link.Name).Msg("could not scan release asset")
		}
	}
	return nil
}

// downloadAndScan streams a GitLab resource through the shared GitLab client so
// retries, rate-limit pauses, and host-scoped auth match API requests.
func (s *GitLab) downloadAndScan(ctx context.Context, rawURL, path string, attrs map[string]string, yield FragmentsFunc) error {
	if err := s.ensureClient(); err != nil {
		return err
	}
	release, err := s.acquireAPISlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	return downloadAndScanSource(ctx, sourceDownloadOptions{
		URL:             rawURL,
		HTTPClient:      s.httpClient,
		Path:            path,
		Attrs:           attrs,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
		TempPattern:     "betterleaks-gitlab-dl-*",
	}, yield)
}

// applyDateRange appends GitLab's standard date-range query parameters when
// DateRangeOpts.Since/Until are set.
func (s *GitLab) applyDateRange(u *url.URL, sinceKey, untilKey string) *url.URL {
	out := *u
	q := out.Query()
	if !s.DateRangeOpts.Since.IsZero() {
		q.Set(sinceKey, s.DateRangeOpts.Since.UTC().Format(time.RFC3339))
	}
	if !s.DateRangeOpts.Until.IsZero() {
		q.Set(untilKey, s.DateRangeOpts.Until.UTC().Format(time.RFC3339))
	}
	out.RawQuery = q.Encode()
	return &out
}

// safePath returns a filesystem-safe form of name suitable for log/artifact
// paths under our temp dirs (no path separators, no leading dots).
func safePath(name string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '_'
		}
	}, name)
	cleaned = strings.TrimLeft(cleaned, ".")
	if cleaned == "" {
		return "unnamed"
	}
	return path.Clean(cleaned)
}

func cloneAttrs(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	maps.Copy(out, m)
	return out
}

func timeOr(primary, fallback time.Time) time.Time {
	if !primary.IsZero() {
		return primary
	}
	return fallback
}

func gitlabNoteURL(parentURL string, noteID int64) string {
	if parentURL == "" || noteID == 0 {
		return parentURL
	}
	u, err := url.Parse(parentURL)
	if err != nil {
		return parentURL + "#note_" + strconv.FormatInt(noteID, 10)
	}
	u.Fragment = "note_" + strconv.FormatInt(noteID, 10)
	return u.String()
}

func (s *GitLab) rateLimitRemaining() int64 {
	if s.restRetry == nil {
		return 0
	}
	return s.restRetry.RateLimitRemaining()
}

func gitlabRetryDecider(req *http.Request, resp *http.Response, err error, now time.Time) (bool, time.Duration) {
	retry, wait := httpclient.DefaultRetryDecider(req, resp, err, now)
	if retry {
		return retry, wait
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		return false, 0
	}
	remaining := firstHeader(resp, "RateLimit-Remaining", "X-RateLimit-Remaining")
	if remaining != "0" {
		return false, 0
	}
	if reset := firstHeader(resp, "RateLimit-Reset", "X-RateLimit-Reset"); reset != "" {
		if epoch, err := strconv.ParseInt(reset, 10, 64); err == nil {
			if d := time.Unix(epoch, 0).Sub(now); d > 0 {
				return true, d
			}
		}
	}
	return true, 60 * time.Second
}

func gitlabRateLimitStateExtractor(resp *http.Response) (int64, time.Time, bool) {
	if resp == nil {
		return 0, time.Time{}, false
	}
	remainingRaw := firstHeader(resp, "RateLimit-Remaining", "X-RateLimit-Remaining")
	resetRaw := firstHeader(resp, "RateLimit-Reset", "X-RateLimit-Reset")
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

func firstHeader(resp *http.Response, keys ...string) string {
	for _, k := range keys {
		if v := resp.Header.Get(k); v != "" {
			return v
		}
	}
	return ""
}
