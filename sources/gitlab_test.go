package sources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseGitLabURL(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		wantPath string
		wantKind string
		wantID   string
		wantErr  bool
	}{
		{name: "root", url: "https://gitlab.com/", wantKind: "namespace"},
		{name: "namespace", url: "https://gitlab.com/group", wantPath: "group", wantKind: "namespace"},
		{name: "nested namespace", url: "https://gitlab.com/group/sub/project", wantPath: "group/sub/project", wantKind: "namespace"},
		{name: "issue", url: "https://gitlab.com/group/project/-/issues/42", wantPath: "group/project", wantKind: "issue", wantID: "42"},
		{name: "merge request", url: "https://gitlab.com/g/sub/p/-/merge_requests/7", wantPath: "g/sub/p", wantKind: "mr", wantID: "7"},
		{name: "snippet", url: "https://gitlab.com/g/p/-/snippets/9", wantPath: "g/p", wantKind: "snippet", wantID: "9"},
		{name: "release", url: "https://gitlab.com/g/p/-/releases/v1.2.3", wantPath: "g/p", wantKind: "release", wantID: "v1.2.3"},
		{name: "pipeline", url: "https://gitlab.com/g/p/-/pipelines/8001", wantPath: "g/p", wantKind: "pipeline", wantID: "8001"},
		{name: "job", url: "https://gitlab.com/g/p/-/jobs/9001", wantPath: "g/p", wantKind: "job", wantID: "9001"},
		{name: "self-hosted with port", url: "https://gitlab.example.com:8443/g/p/-/issues/1", wantPath: "g/p", wantKind: "issue", wantID: "1"},
		{name: "unsupported resource", url: "https://gitlab.com/g/p/-/wiki/Home", wantErr: true},
		{name: "missing id", url: "https://gitlab.com/g/p/-/issues", wantErr: true},
		{name: "bad scheme", url: "ftp://gitlab.com/g/p", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseGitLabURL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", got.ID, tc.wantID)
			}
		})
	}
}

func TestGitLab_isExcluded(t *testing.T) {
	s := &GitLab{ExcludeRepos: []string{"group/test-*", "OTHER/abandoned"}}
	cases := map[string]bool{
		"group/test-foo":     true,
		"group/Test-Bar":     true, // case-insensitive
		"other/abandoned":    true,
		"group/keep-me":      false,
		"unrelated/anything": false,
	}
	for path, want := range cases {
		if got := s.isExcluded(path); got != want {
			t.Errorf("isExcluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestGitLab_projectAttributes(t *testing.T) {
	proj := &gitlabProject{
		ID:                42,
		PathWithNamespace: "group/sub/project",
		Visibility:        "private",
		WebURL:            "https://gitlab.com/group/sub/project",
	}
	proj.Namespace.FullPath = "group/sub"
	s := &GitLab{}

	got := s.projectAttributes(proj, ResourceGitLabProject)
	want := map[string]string{
		AttrGitLabProjectID:   "42",
		AttrGitLabProjectPath: "group/sub/project",
		AttrGitLabProjectURL:  "https://gitlab.com/group/sub/project",
		AttrGitLabVisibility:  "private",
		AttrGitLabNamespace:   "group/sub",
		AttrResource:          ResourceGitLabProject,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attr %q = %q, want %q", k, got[k], v)
		}
	}

	// resource is empty → no AttrResource key set
	bare := s.projectAttributes(proj, "")
	if _, ok := bare[AttrResource]; ok {
		t.Errorf("expected no AttrResource when resource=\"\", got %q", bare[AttrResource])
	}
}

func TestGitLab_Validate(t *testing.T) {
	cases := []struct {
		name      string
		source    func() *GitLab
		wantErr   bool
		wantResrc []GitLabResourceType
	}{
		{
			name:    "missing URL",
			source:  func() *GitLab { return &GitLab{Token: "t"} },
			wantErr: true,
		},
		{
			name:    "namespace URL without token",
			source:  func() *GitLab { return &GitLab{URL: "https://gitlab.com/group"} },
			wantErr: true,
		},
		{
			name:    "project URL without token",
			source:  func() *GitLab { return &GitLab{URL: "https://gitlab.com/group/project"} },
			wantErr: true, // namespace kind → requires token
		},
		{
			name:      "release URL stamps release+assets default",
			source:    func() *GitLab { return &GitLab{URL: "https://gitlab.com/g/p/-/releases/v1.0", Token: "t"} },
			wantResrc: []GitLabResourceType{GitLabResourceTypeReleases, GitLabResourceTypeReleaseAssets},
		},
		{
			name:    "include unknown",
			source:  func() *GitLab { return &GitLab{URL: "https://gitlab.com/g/p", Token: "t", Include: []string{"bogus"}} },
			wantErr: true,
		},
		{
			name:      "exclude drops resource",
			source:    func() *GitLab { return &GitLab{URL: "https://gitlab.com/g/p/-/releases/v1", Token: "t", Exclude: []string{"release-assets"}} },
			wantResrc: []GitLabResourceType{GitLabResourceTypeReleases},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.source()
			err := src.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, rt := range tc.wantResrc {
				if !src.Resources.Has(rt) {
					t.Errorf("expected Resources to have %q; got %v", rt, src.Resources)
				}
			}
		})
	}
}

// TestGitLab_scanProject_L1Skip: when ShouldSkip returns true for a
// project's L1 attrs, no fragments are yielded — even for resource types
// that are enabled, because the per-resource scanners are never reached.
func TestGitLab_scanProject_L1Skip(t *testing.T) {
	skipped := 0
	s := &GitLab{
		Resources: GitLabResourceSet{GitLabResourceTypeIssues: true},
		ShouldSkip: func(attrs map[string]string) bool {
			if attrs[AttrResource] == ResourceGitLabProject {
				skipped++
				return true
			}
			return false
		},
	}
	proj := &gitlabProject{ID: 1, PathWithNamespace: "g/p", WebURL: "https://gitlab.com/g/p"}

	yielded := 0
	yield := func(f Fragment, err error) error { yielded++; return nil }
	if err := s.scanProject(context.Background(), proj, yield); err != nil {
		t.Fatalf("scanProject: %v", err)
	}
	if skipped != 1 {
		t.Errorf("expected L1 skip to fire exactly once, got %d", skipped)
	}
	if yielded != 0 {
		t.Errorf("expected 0 fragments, got %d", yielded)
	}
}

// TestGitLab_scanIssues_L2Skip: an item-level ShouldSkip drops a specific
// issue (and crucially does NOT fetch its notes), but lets other issues through.
func TestGitLab_scanIssues_L2Skip(t *testing.T) {
	var notesFetchedFor []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/issues"):
			page, _ := json.Marshal([]gitlabIssue{
				{IID: 1, Title: "keep me", Description: "body1", WebURL: "https://example/issues/1", CreatedAt: time.Now()},
				{IID: 2, Title: "drop me", Description: "body2", WebURL: "https://example/issues/2", CreatedAt: time.Now()},
			})
			w.Header().Set("X-Next-Page", "")
			_, _ = w.Write(page)
		case strings.Contains(r.URL.Path, "/notes"):
			// Track which issue's notes were requested.
			notesFetchedFor = append(notesFetchedFor, r.URL.Path)
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s := &GitLab{
		URL:        server.URL + "/g/p/-/issues/0",
		BaseURL:    server.URL + "/",
		Token:      "t",
		Resources:  GitLabResourceSet{GitLabResourceTypeIssues: true, GitLabResourceTypeIssueComments: true},
		ShouldSkip: func(attrs map[string]string) bool { return attrs[AttrGitLabIssueIID] == "2" },
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if base, err := s.buildAPIBase(); err != nil {
		t.Fatalf("buildAPIBase: %v", err)
	} else {
		s.apiBaseURL = base
		s.httpClient = http.DefaultClient
	}
	proj := &gitlabProject{ID: 1, PathWithNamespace: "g/p"}

	var got []string
	var mu sync.Mutex
	yield := func(f Fragment, err error) error {
		if err != nil {
			return err
		}
		mu.Lock()
		got = append(got, f.Attr(AttrGitLabIssueIID))
		mu.Unlock()
		return nil
	}
	if err := s.scanIssues(context.Background(), proj, yield); err != nil {
		t.Fatalf("scanIssues: %v", err)
	}
	if want := []string{"1"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("yielded issue IIDs = %v, want %v", got, want)
	}
	// The dropped issue (IID=2) must NOT have had its notes fetched —
	// that's the entire point of an L2 skip.
	for _, p := range notesFetchedFor {
		if strings.Contains(p, "/issues/2/") {
			t.Errorf("notes fetched for skipped issue: %s", p)
		}
	}
}

// TestGitLab_wrapGitLabYield_stampsAndSkips: the L3 wrapper stamps project
// attrs on incoming fragments and applies the per-fragment skip filter.
func TestGitLab_wrapGitLabYield_stampsAndSkips(t *testing.T) {
	projectAttrs := map[string]string{
		AttrGitLabProjectID:   "1",
		AttrGitLabProjectPath: "g/p",
	}
	var got []map[string]string
	yield := func(f Fragment, err error) error {
		got = append(got, f.Attributes)
		return nil
	}

	skip := func(attrs map[string]string) bool {
		return attrs[AttrGitSHA] == "deadbeef"
	}
	wrapped := wrapGitLabYield(skip, projectAttrs, yield)

	// 1) Fragment with no overlap → both attrs stamped, not skipped.
	_ = wrapped(Fragment{Attributes: map[string]string{AttrGitSHA: "cafe"}}, nil)
	// 2) Fragment matching skip predicate → dropped.
	_ = wrapped(Fragment{Attributes: map[string]string{AttrGitSHA: "deadbeef"}}, nil)
	// 3) Fragment with overlapping attr → existing value preserved.
	_ = wrapped(Fragment{Attributes: map[string]string{AttrGitLabProjectID: "999"}}, nil)

	if len(got) != 2 {
		t.Fatalf("yielded %d fragments, want 2", len(got))
	}
	if got[0][AttrGitLabProjectID] != "1" || got[0][AttrGitLabProjectPath] != "g/p" {
		t.Errorf("first fragment missing stamped project attrs: %v", got[0])
	}
	if got[1][AttrGitLabProjectID] != "999" {
		t.Errorf("overlapping attr should not be overwritten; got %v", got[1])
	}
}

func TestGitlabRetryDecider_PrimaryRateLimit403(t *testing.T) {
	now := time.Now()
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{},
	}
	resp.Header.Set("RateLimit-Remaining", "0")
	resp.Header.Set("RateLimit-Reset", "9999999999") // far future
	retry, wait := gitlabRetryDecider(nil, resp, nil, now)
	if !retry {
		t.Fatal("expected retry=true for primary rate limit")
	}
	if wait <= 0 {
		t.Errorf("expected positive wait, got %v", wait)
	}

	// Without RateLimit-Remaining=0, 403 should NOT trigger retry.
	resp.Header.Set("RateLimit-Remaining", "10")
	if r, _ := gitlabRetryDecider(nil, resp, nil, now); r {
		t.Errorf("expected no retry for ordinary 403")
	}
}

func TestGitlabRateLimitStateExtractor_ParsesBothHeaderForms(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    int64
	}{
		{name: "no-prefix", headers: map[string]string{"RateLimit-Remaining": "42"}, want: 42},
		{name: "x-prefix", headers: map[string]string{"X-RateLimit-Remaining": "7"}, want: 7},
		{name: "absent", headers: nil, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			for k, v := range tc.headers {
				resp.Header.Set(k, v)
			}
			remaining, _, ok := gitlabRateLimitStateExtractor(resp)
			if tc.headers == nil {
				if ok {
					t.Errorf("expected ok=false with no headers")
				}
				return
			}
			if !ok {
				t.Fatal("expected ok=true with headers present")
			}
			if remaining != tc.want {
				t.Errorf("remaining = %d, want %d", remaining, tc.want)
			}
		})
	}
}

func TestGitLab_buildAPIBase(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{base: "https://gitlab.com/", want: "https://gitlab.com/api/v4/"},
		{base: "https://gitlab.com", want: "https://gitlab.com/api/v4/"},
		{base: "https://corp.com/gitlab/", want: "https://corp.com/gitlab/api/v4/"},
		{base: "https://gitlab.example.com:8443/", want: "https://gitlab.example.com:8443/api/v4/"},
	}
	for _, tc := range cases {
		t.Run(tc.base, func(t *testing.T) {
			s := &GitLab{BaseURL: tc.base}
			u, err := s.buildAPIBase()
			if err != nil {
				t.Fatalf("buildAPIBase: %v", err)
			}
			if u.String() != tc.want {
				t.Errorf("got %q, want %q", u.String(), tc.want)
			}
		})
	}
}
