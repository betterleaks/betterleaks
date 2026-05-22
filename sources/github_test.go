package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/semgroup"
	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/internal/celenv"
	"github.com/betterleaks/betterleaks/internal/httpclient"
)

func TestGitHub_scanRepo_prefilterSkipsRepoByResourceAttrs(t *testing.T) {
	t.Parallel()

	repoPath := createGitHubTestRepo(t)
	skip := compileGitHubPrefilter(t, `attributes[?"resource"].orValue("") == "github.repository" && attributes[?"github.repo"].orValue("") == "repo"`)

	src := &GitHub{ShouldSkip: skip, Sema: semgroup.NewGroup(t.Context(), 4), Resources: GitHubResourceSet{GitHubResourceTypeRepos: true}}
	repo := newTestGitHubRepo(repoPath)

	var fragments []Fragment
	err := src.scanRepo(t.Context(), nil, repo, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, fragments)
}

func TestGitHub_scanRepo_prefilterUsesMergedRepoAttrsOnFragments(t *testing.T) {
	t.Parallel()

	repoPath := createGitHubTestRepo(t)
	skip := compileGitHubPrefilter(t, `attributes[?"github.repo"].orValue("") == "repo" && attributes[?"path"].orValue("") != ""`)

	src := &GitHub{ShouldSkip: skip, Sema: semgroup.NewGroup(t.Context(), 4), Resources: GitHubResourceSet{GitHubResourceTypeRepos: true}}
	repo := newTestGitHubRepo(repoPath)

	var fragments []Fragment
	err := src.scanRepo(t.Context(), nil, repo, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, fragments)
}

func TestGitHub_scanRepo_yieldsFragmentsWithoutMatchingPrefilter(t *testing.T) {
	t.Parallel()

	repoPath := createGitHubTestRepo(t)
	skip := compileGitHubPrefilter(t, `containsAny(attributes[?"path"].orValue(""), ["does-not-match"])`)

	src := &GitHub{ShouldSkip: skip, Sema: semgroup.NewGroup(t.Context(), 4), Resources: GitHubResourceSet{GitHubResourceTypeRepos: true}}
	repo := newTestGitHubRepo(repoPath)

	var fragments []Fragment
	err := src.scanRepo(t.Context(), nil, repo, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, fragments)
	require.Contains(t, fragments[0].Raw, "AKIALALEMEL33243OLIA")
	require.Equal(t, "repo", fragments[0].Attr(AttrGitHubRepo))
	require.Equal(t, "owner", fragments[0].Attr(AttrGitHubOwner))
	require.NotEmpty(t, fragments[0].Attr(AttrPath))
}

func TestGitHub_scanRepo_skipRepoGitDoesNotCloneOrScanHistory(t *testing.T) {
	t.Parallel()

	src := &GitHub{
		Resources: GitHubResourceSet{}, // repos not in set = skip git
		Sema:      semgroup.NewGroup(t.Context(), 4),
	}
	repo := newTestGitHubRepo(filepath.Join(t.TempDir(), "does-not-exist"))

	var fragments []Fragment
	err := src.scanRepo(t.Context(), nil, repo, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, fragments)
}

func TestGitHub_scanURL_gistDoesNotPanicAndStampsAttrs(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/gists/abc123def456":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"id":       "abc123def456",
				"html_url": "https://gist.github.example.com/user/abc123def456",
				"files": map[string]any{
					"secret.txt": map[string]any{
						"filename": "secret.txt",
						"type":     "text/plain",
						"content":  "token=AKIALALEMEL33243OLIA\n",
					},
				},
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	src := &GitHub{
		BaseURL:   strings.TrimRight(server.URL, "/") + "/api/v3/",
		URL:       "https://gist.github.example.com/user/abc123def456",
		restRetry: httpclient.NewRetryTransport(nil),
	}
	client := src.newClient(t.Context())

	var fragments []Fragment
	require.NotPanics(t, func() {
		err := src.scanURL(t.Context(), client, src.URL, func(fragment Fragment, err error) error {
			require.NoError(t, err)
			fragments = append(fragments, fragment)
			return nil
		})
		require.NoError(t, err)
	})

	require.Len(t, fragments, 1)
	require.Equal(t, ResourceGitHubGist, fragments[0].Attr(AttrResource))
	require.Equal(t, "abc123def456", fragments[0].Attr(AttrGitHubGistID))
	require.Equal(t, "user", fragments[0].Attr(AttrGitHubGistOwner))
	require.Equal(t, "secret.txt", fragments[0].Attr(AttrGitHubGistFilename))
	require.Equal(t, "https://gist.github.example.com/user/abc123def456", fragments[0].Attr(AttrURL))
	require.Contains(t, fragments[0].Raw, "AKIALALEMEL33243OLIA")
}

func TestGitHub_emitIssueAndComments_stampsAttrs(t *testing.T) {
	t.Parallel()

	src := &GitHub{Resources: GitHubResourceSet{GitHubResourceTypeIssues: true, GitHubResourceTypeIssueComments: true}}
	issueURL := "https://github.example.com/owner/repo/issues/42"
	now := time.Now().UTC()
	issue := ghIssueNode{
		Number:    42,
		Title:     "Issue title",
		Body:      "Issue body",
		Url:       issueURL,
		CreatedAt: now,
		Comments: ghCommentConnection{
			Nodes: []ghComment{{
				DatabaseId: 101,
				Body:       "Issue comment",
				CreatedAt:  now,
			}},
		},
	}

	var fragments []Fragment
	var commentCount int
	err := src.emitIssueAndComments(t.Context(), "owner", "repo", issue, &commentCount, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, fragments, 2)
	require.Equal(t, 1, commentCount)

	require.Equal(t, ResourceGitHubIssue, fragments[0].Attr(AttrResource))
	require.Equal(t, "42", fragments[0].Attr(AttrGitHubIssueNumber))
	require.Equal(t, issueURL, fragments[0].Attr(AttrURL))
	require.Contains(t, fragments[0].Raw, "Issue title")

	require.Equal(t, ResourceGitHubComment, fragments[1].Attr(AttrResource))
	require.Equal(t, "101", fragments[1].Attr(AttrGitHubCommentID))
	require.Equal(t, "42", fragments[1].Attr(AttrGitHubIssueNumber))
	require.Equal(t, issueURL, fragments[1].Attr(AttrURL))
	require.Equal(t, "Issue comment", fragments[1].Raw)
}

func TestGithubRetryDecider_PrimaryRateLimit403(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h := http.Header{}
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(15*time.Second).Unix(), 10))
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     h,
	}
	retry, wait := githubRetryDecider(nil, resp, nil, now)
	require.True(t, retry)
	require.GreaterOrEqual(t, wait, 14*time.Second)
	require.LessOrEqual(t, wait, 16*time.Second)
}

func TestGithubRateLimitStateExtractor_ParsesHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-RateLimit-Remaining", "7")
	h.Set("X-RateLimit-Reset", "1700000015")
	resp := &http.Response{
		Header: h,
	}
	remaining, resetAt, ok := githubRateLimitStateExtractor(resp)
	require.True(t, ok)
	require.EqualValues(t, 7, remaining)
	require.EqualValues(t, 1700000015, resetAt.Unix())
}

func TestGitHub_emitPRAndComments_stampsPRAndReviewThreadAttrs(t *testing.T) {
	t.Parallel()

	src := &GitHub{Resources: GitHubResourceSet{GitHubResourceTypePRs: true, GitHubResourceTypePRComments: true}}
	prURL := "https://github.example.com/owner/repo/pull/7"
	now := time.Now().UTC()
	pr := ghPRNode{
		Number:    7,
		Title:     "PR title",
		Body:      "PR body",
		Url:       prURL,
		CreatedAt: now,
		Comments: ghCommentConnection{
			Nodes: []ghComment{{
				DatabaseId: 201,
				Body:       "PR comment",
				CreatedAt:  now,
			}},
		},
		ReviewThreads: ghReviewThreadConnection{
			Nodes: []ghReviewThreadNode{{
				Comments: ghCommentConnection{Nodes: []ghComment{{
					DatabaseId: 202,
					Body:       "Review thread comment",
					CreatedAt:  now,
				}}},
			}},
		},
	}

	var fragments []Fragment
	var commentCount int
	err := src.emitPRAndComments(t.Context(), "owner", "repo", pr, &commentCount, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, fragments, 3)
	require.Equal(t, 2, commentCount)

	require.Equal(t, ResourceGitHubPR, fragments[0].Attr(AttrResource))
	require.Equal(t, "7", fragments[0].Attr(AttrGitHubPRNumber))
	require.Equal(t, prURL, fragments[0].Attr(AttrURL))

	for _, fragment := range fragments[1:] {
		require.Equal(t, ResourceGitHubComment, fragment.Attr(AttrResource))
		require.Equal(t, "7", fragment.Attr(AttrGitHubPRNumber))
		require.Equal(t, prURL, fragment.Attr(AttrURL))
	}
	require.Equal(t, "201", fragments[1].Attr(AttrGitHubCommentID))
	require.Equal(t, "202", fragments[2].Attr(AttrGitHubCommentID))
}

func TestGitHub_emitDiscussion_stampsDiscussionCommentAndReplyAttrs(t *testing.T) {
	t.Parallel()

	src := &GitHub{Resources: GitHubResourceSet{GitHubResourceTypeDiscussions: true}}
	discussionURL := "https://github.example.com/owner/repo/discussions/9"
	now := time.Now().UTC()
	discussion := ghDiscussionNode{
		Number:    9,
		Title:     "Discussion title",
		Body:      "Discussion body",
		Url:       discussionURL,
		CreatedAt: now,
		Comments: ghDiscussionCommentConnection{
			Nodes: []ghDiscussionComment{{
				DatabaseId: 301,
				Body:       "Discussion comment",
				CreatedAt:  now,
				Replies: struct {
					Nodes    []ghDiscussionCommentReply
					PageInfo ghPageInfo
				}{
					Nodes: []ghDiscussionCommentReply{{
						DatabaseId: 302,
						Body:       "Discussion reply",
						CreatedAt:  now,
					}},
				},
			}},
		},
	}

	var fragments []Fragment
	var commentCount int
	err := src.emitDiscussion(t.Context(), "owner", "repo", discussion, &commentCount, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, fragments, 3)
	require.Equal(t, 2, commentCount)

	require.Equal(t, ResourceGitHubDiscussion, fragments[0].Attr(AttrResource))
	require.Equal(t, "9", fragments[0].Attr(AttrGitHubDiscussionNumber))
	require.Equal(t, discussionURL, fragments[0].Attr(AttrURL))

	for _, fragment := range fragments[1:] {
		require.Equal(t, ResourceGitHubComment, fragment.Attr(AttrResource))
		require.Equal(t, "9", fragment.Attr(AttrGitHubDiscussionNumber))
		require.Equal(t, discussionURL, fragment.Attr(AttrURL))
	}
	require.Equal(t, "301", fragments[1].Attr(AttrGitHubCommentID))
	require.Equal(t, "302", fragments[2].Attr(AttrGitHubCommentID))
}

func TestGitHub_emitRelease_stampsReleaseAttrs(t *testing.T) {
	t.Parallel()

	tag := "v1.0.0"
	releaseName := "Release title"
	body := "Release body"
	htmlURL := "https://github.example.com/owner/repo/releases/tag/v1.0.0"
	rel := &github.RepositoryRelease{
		TagName: &tag,
		Name:    &releaseName,
		Body:    &body,
		HTMLURL: &htmlURL,
	}

	src := &GitHub{Resources: GitHubResourceSet{GitHubResourceTypeReleases: true}}
	var fragments []Fragment
	err := src.emitRelease(t.Context(), nil, nil, "owner", "repo", rel, func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, fragments, 1)
	require.Equal(t, ResourceGitHubRelease, fragments[0].Attr(AttrResource))
	require.Equal(t, tag, fragments[0].Attr(AttrGitHubReleaseTag))
	require.Equal(t, htmlURL, fragments[0].Attr(AttrURL))
	require.Contains(t, fragments[0].Raw, releaseName)
}

func TestGitHub_emitRelease_prefilterSkipsReleaseByTag(t *testing.T) {
	t.Parallel()

	tag := "v1.0.0"
	htmlURL := "https://github.example.com/owner/repo/releases/tag/v1.0.0"
	rel := &github.RepositoryRelease{
		TagName: &tag,
		HTMLURL: &htmlURL,
	}

	src := &GitHub{
		Resources:  GitHubResourceSet{GitHubResourceTypeReleases: true},
		ShouldSkip: compileGitHubPrefilter(t, `attributes[?"resource"].orValue("") == "github.release" && attributes[?"github.release.tag"].orValue("") == "v1.0.0"`),
	}

	called := false
	err := src.emitRelease(t.Context(), nil, nil, "owner", "repo", rel, func(fragment Fragment, err error) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	require.False(t, called)
}

func TestGitHub_downloadAndScanZip_stampsActionsAttrs(t *testing.T) {
	t.Parallel()

	zipBytes := buildGitHubTestZip(t, map[string]string{
		"job.log": "token=AKIALALEMEL33243OLIA\n",
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, err := w.Write(zipBytes)
		require.NoError(t, err)
	}))
	defer server.Close()

	zipURL, err := url.Parse(server.URL + "/logs.zip")
	require.NoError(t, err)

	runID := int64(123)
	runName := "CI"
	runURL := "https://github.example.com/owner/repo/actions/runs/123"
	event := "push"
	run := &github.WorkflowRun{
		ID:      &runID,
		Name:    &runName,
		HTMLURL: &runURL,
		Event:   &event,
	}

	src := &GitHub{MaxArchiveDepth: 2}
	runIDStr := strconv.FormatInt(run.GetID(), 10)
	zipPath := "actions/logs/run_" + runIDStr + ".zip"
	actionsAttrs := map[string]string{
		AttrGitHubActionsRunID:   runIDStr,
		AttrGitHubActionsRunName: run.GetName(),
		AttrGitHubActionsRunURL:  run.GetHTMLURL(),
		AttrGitHubActionsEvent:   run.GetEvent(),
		AttrResource:             ResourceGitHubActions,
	}
	var fragments []Fragment
	err = src.downloadAndScan(t.Context(), zipURL.String(), nil, zipPath, actionsAttrs, "", func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, fragments)

	fragment := fragments[0]
	require.Equal(t, ResourceGitHubActions, fragment.Attr(AttrResource))
	require.Equal(t, "123", fragment.Attr(AttrGitHubActionsRunID))
	require.Equal(t, runName, fragment.Attr(AttrGitHubActionsRunName))
	require.Equal(t, runURL, fragment.Attr(AttrGitHubActionsRunURL))
	require.Equal(t, event, fragment.Attr(AttrGitHubActionsEvent))
	require.Contains(t, fragment.Raw, "AKIALALEMEL33243OLIA")
	require.Contains(t, fragment.Attr(AttrPath), "actions/logs")
}

// TestGitHub_downloadAndScan_bearerToken pins the contract that downloadAndScan
// only sends the GitHub token when the caller explicitly opts in. Callers that
// hand it an already-resolved CDN URL (Actions logs / artifacts) pass "" so
// the credential does not leak into third-party storage access logs; callers
// hitting api.github.com / a configured GHE host pass s.Token so private
// resources still authenticate.
func TestGitHub_downloadAndScan_bearerToken(t *testing.T) {
	t.Parallel()

	zipBytes := buildGitHubTestZip(t, map[string]string{
		"job.log": "ok\n",
	})

	tests := []struct {
		name     string
		token    string
		wantAuth string
	}{
		{name: "empty token omits Authorization header", token: "", wantAuth: ""},
		{name: "non-empty token sends Bearer auth", token: "ghp_super_secret", wantAuth: "Bearer ghp_super_secret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/zip")
				_, err := w.Write(zipBytes)
				require.NoError(t, err)
			}))
			defer server.Close()

			// Token field on src is intentionally set to a value that would
			// fail the empty-token assertion if it were used by mistake.
			src := &GitHub{Token: "ghp_must_not_leak", MaxArchiveDepth: 2}
			err := src.downloadAndScan(t.Context(), server.URL+"/blob.zip", nil, "p/blob.zip", nil, tc.token, func(_ Fragment, err error) error {
				return err
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantAuth, gotAuth)
		})
	}
}

func TestGitHub_scanActions_startsLogsBeforeWorkflowPaginationCompletes(t *testing.T) {
	t.Parallel()

	logZip := buildGitHubTestZip(t, map[string]string{
		"job.log": "token=AKIALALEMEL33243OLIA\n",
	})
	pageTwoRequested := make(chan struct{})
	logsStarted := make(chan struct{})
	releasePageTwo := make(chan struct{})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs" && r.URL.Query().Get("page") == "2":
			close(pageTwoRequested)
			<-releasePageTwo
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"total_count":1,"workflow_runs":[]}`)
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Link", `<`+server.URL+`/api/v3/repos/owner/repo/actions/runs?page=2>; rel="next"`)
			fmt.Fprint(w, `{"total_count":1,"workflow_runs":[{"id":101,"name":"CI","html_url":"https://github.example.com/owner/repo/actions/runs/101","event":"push"}]}`)
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs/101/logs":
			close(logsStarted)
			w.Header().Set("Location", server.URL+"/downloads/logs/101.zip")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/downloads/logs/101.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, err := w.Write(logZip)
			require.NoError(t, err)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	src := &GitHub{
		BaseURL:         strings.TrimRight(server.URL, "/") + "/api/v3/",
		MaxArchiveDepth: 2,
		Resources:       GitHubResourceSet{GitHubResourceTypeActions: true},
	}
	repo := newTestGitHubRepo(t.TempDir())
	client := src.newClient(t.Context())

	errCh := make(chan error, 1)
	go func() {
		errCh <- src.scanActions(t.Context(), client, repo, func(Fragment, error) error { return nil })
	}()

	select {
	case <-pageTwoRequested:
	case <-time.After(2 * time.Second):
		t.Fatal("workflow run pagination never requested page 2")
	}

	select {
	case <-logsStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("run log scan did not start before workflow pagination completed")
	}

	close(releasePageTwo)
	require.NoError(t, <-errCh)
	select {
	case <-logsStarted:
	default:
		t.Fatal("expected logs to start scanning")
	}
	select {
	case <-pageTwoRequested:
	default:
		t.Fatal("expected workflow pagination to request page 2")
	}
}

func TestGitHub_scanActions_startsArtifactsBeforeWorkflowPaginationCompletes(t *testing.T) {
	t.Parallel()

	logZip := buildGitHubTestZip(t, map[string]string{
		"job.log": "token=AKIALALEMEL33243OLIA\n",
	})
	artifactZip := buildGitHubTestZip(t, map[string]string{
		"artifact.txt": "token=AKIALALEMEL33243OLIA\n",
	})
	pageTwoRequested := make(chan struct{})
	artifactListStarted := make(chan struct{})
	releasePageTwo := make(chan struct{})

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs" && r.URL.Query().Get("page") == "2":
			close(pageTwoRequested)
			<-releasePageTwo
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"total_count":1,"workflow_runs":[]}`)
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Link", `<`+server.URL+`/api/v3/repos/owner/repo/actions/runs?page=2>; rel="next"`)
			fmt.Fprint(w, `{"total_count":1,"workflow_runs":[{"id":202,"name":"CI","html_url":"https://github.example.com/owner/repo/actions/runs/202","event":"push"}]}`)
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs/202/logs":
			w.Header().Set("Location", server.URL+"/downloads/logs/202.zip")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/downloads/logs/202.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, err := w.Write(logZip)
			require.NoError(t, err)
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/runs/202/artifacts":
			close(artifactListStarted)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"total_count":1,"artifacts":[{"id":303,"name":"bundle","expired":false}]}`)
		case r.URL.Path == "/api/v3/repos/owner/repo/actions/artifacts/303/zip":
			w.Header().Set("Location", server.URL+"/downloads/artifacts/303.zip")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/downloads/artifacts/303.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, err := w.Write(artifactZip)
			require.NoError(t, err)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	src := &GitHub{
		BaseURL:         strings.TrimRight(server.URL, "/") + "/api/v3/",
		MaxArchiveDepth: 2,
		Resources: GitHubResourceSet{
			GitHubResourceTypeActions:         true,
			GitHubResourceTypeActionArtifacts: true,
		},
	}
	repo := newTestGitHubRepo(t.TempDir())
	client := src.newClient(t.Context())

	errCh := make(chan error, 1)
	go func() {
		errCh <- src.scanActions(t.Context(), client, repo, func(Fragment, error) error { return nil })
	}()

	select {
	case <-pageTwoRequested:
	case <-time.After(2 * time.Second):
		t.Fatal("workflow run pagination never requested page 2")
	}

	select {
	case <-artifactListStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("artifact scan did not start before workflow pagination completed")
	}

	close(releasePageTwo)
	require.NoError(t, <-errCh)
}

func TestGitHub_streamWorkflowRuns_usesCombinedCreatedRange(t *testing.T) {
	t.Parallel()

	since := time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC)

	var createdQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/owner/repo/actions/runs":
			createdQuery = r.URL.Query().Get("created")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"total_count":1,"workflow_runs":[{"id":12,"name":"in-range","html_url":"https://github.example.com/owner/repo/actions/runs/12","event":"push","created_at":"2026-05-03T00:00:00Z"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	src := &GitHub{
		BaseURL: strings.TrimRight(server.URL, "/") + "/api/v3/",
		DateRangeOpts: DateRangeOptions{
			Since: since,
			Until: until,
		},
	}
	client := src.newClient(t.Context())

	var got []int64
	err := src.streamWorkflowRuns(t.Context(), client, "owner", "repo", func(run *github.WorkflowRun) error {
		got = append(got, run.GetID())
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "2026-05-02..2026-05-04", createdQuery)
	require.Equal(t, []int64{12}, got)
}

func compileGitHubPrefilter(t *testing.T, expression string) SkipFunc {
	t.Helper()

	env, err := celenv.NewPrefilterEnv()
	require.NoError(t, err)
	prg, err := env.Compile(expression)
	require.NoError(t, err)

	return func(attrs map[string]string) bool {
		skip, err := celenv.EvalPrefilter(prg, attrs)
		require.NoError(t, err)
		return skip
	}
}

func newTestGitHubRepo(repoPath string) *github.Repository {
	owner := "owner"
	ownerType := "User"
	name := "repo"
	fullName := owner + "/" + name
	htmlURL := "https://github.example.com/owner/repo"
	visibility := "private"
	cloneURL := repoPath

	return &github.Repository{
		Name:       &name,
		FullName:   &fullName,
		CloneURL:   &cloneURL,
		HTMLURL:    &htmlURL,
		Visibility: &visibility,
		Owner: &github.User{
			Login: &owner,
			Type:  &ownerType,
		},
	}
}

func createGitHubTestRepo(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	repoDir := filepath.Join(root, "repo")
	require.NoError(t, os.Mkdir(repoDir, 0o755))

	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.name", "Test User")
	runGit(t, repoDir, "config", "user.email", "user@example.com")

	secretPath := filepath.Join(repoDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretPath, []byte("token=AKIALALEMEL33243OLIA\n"), 0o644))
	runGit(t, repoDir, "add", "secret.txt")
	runGit(t, repoDir, "commit", "-m", "seed test repo")

	return repoDir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, fmt.Sprintf("%s", out))
	}
}

func buildGitHubTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestFragments_A2_schedulesAllReposAboveConcurrencyLimit verifies that when
// more than 8 repos are present, every repo is eventually scanned.
// Before A2 the fix (TryGo→Go), repos beyond the semgroup limit were silently
// dropped.
func TestFragments_A2_schedulesAllReposAboveConcurrencyLimit(t *testing.T) {
	t.Parallel()

	const numRepos = 12

	var mu sync.Mutex
	scannedReleases := make(map[string]bool)

	repos := make([]string, numRepos)
	for i := range repos {
		repos[i] = fmt.Sprintf("repo%d", i)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if r.URL.Path == "/api/v3/users/owner" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"login":"owner","type":"User"}`)
			return
		}
		if r.URL.Path == "/api/v3/users/owner/repos" {
			w.Header().Set("Content-Type", "application/json")
			var out []map[string]any
			for _, repoName := range repos {
				out = append(out, map[string]any{
					"id": 1, "name": repoName, "full_name": "owner/" + repoName, "private": false,
					"fork": false, "html_url": "https://github.example.com/owner/" + repoName,
					"clone_url": "https://github.example.com/owner/" + repoName + ".git",
					"owner":     map[string]any{"login": "owner", "type": "User"},
				})
			}
			require.NoError(t, json.NewEncoder(w).Encode(out))
			return
		}
		// GET /api/v3/repos/owner/{repo}  — fetchRepo
		if len(parts) == 5 && parts[0] == "api" && parts[1] == "v3" && parts[2] == "repos" {
			repoName := parts[4]
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":1,"name":%q,"full_name":"owner/%[1]s","private":false,"fork":false,"html_url":"https://github.example.com/owner/%[1]s","clone_url":"https://github.example.com/owner/%[1]s.git","owner":{"login":"owner","type":"User"}}`, repoName)
			return
		}
		// GET /api/v3/repos/owner/{repo}/releases
		if len(parts) == 6 && parts[5] == "releases" {
			mu.Lock()
			scannedReleases[parts[4]] = true
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "[]")
			return
		}
		// GraphQL — return empty to avoid panics when gqlClient is initialised.
		if r.URL.Path == "/api/graphql" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":{}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	src := &GitHub{
		BaseURL:   strings.TrimRight(server.URL, "/") + "/api/v3/",
		URL:       "https://github.example.com/owner",
		Token:     "tok",
		Resources: GitHubResourceSet{GitHubResourceTypeReleases: true},
	}
	err := src.Fragments(t.Context(), func(_ Fragment, _ error) error { return nil })
	require.NoError(t, err)

	mu.Lock()
	got := len(scannedReleases)
	mu.Unlock()
	require.Equal(t, numRepos, got, "expected all %d repos to be scanned for releases, got %d", numRepos, got)
}

// TestFragments_A3_enumErrWaitsForScans verifies that when enumeration fails,
// Fragments cancels and waits for all in-flight scans to finish before returning,
// so yield is never called after Fragments returns.
func TestFragments_A3_enumErrWaitsForScans(t *testing.T) {
	t.Parallel()

	// scanStarted is closed when repo0's scan first hits the releases endpoint.
	scanStarted := make(chan struct{})
	var scanStartedOnce sync.Once
	// badRepoReady allows the second repo-list page to proceed (and fail 404).
	badRepoReady := make(chan struct{})

	var mu sync.Mutex
	done := false
	yieldAfterDone := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if r.URL.Path == "/api/v3/users/owner" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"login":"owner","type":"User"}`)
			return
		}
		if r.URL.Path == "/api/v3/users/owner/repos" {
			if r.URL.Query().Get("page") == "2" {
				<-badRepoReady
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Link", `<http://`+r.Host+`/api/v3/users/owner/repos?page=2>; rel="next"`)
			fmt.Fprint(w, `[{"id":1,"name":"repo0","full_name":"owner/repo0","private":false,"fork":false,"html_url":"https://github.example.com/owner/repo0","clone_url":"https://github.example.com/owner/repo0.git","owner":{"login":"owner","type":"User"}}]`)
			return
		}
		// fetchRepo: /api/v3/repos/owner/{repo}
		if len(parts) == 5 && parts[0] == "api" && parts[1] == "v3" && parts[2] == "repos" && len(parts[4]) > 0 {
			repoName := parts[4]
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":1,"name":%q,"full_name":"owner/%[1]s","private":false,"fork":false,"html_url":"https://github.example.com/owner/%[1]s","clone_url":"https://github.example.com/owner/%[1]s.git","owner":{"login":"owner","type":"User"}}`, repoName)
			return
		}
		// releases: /api/v3/repos/owner/{repo}/releases
		if len(parts) == 6 && parts[0] == "api" && parts[1] == "v3" && parts[2] == "repos" && parts[5] == "releases" {
			// Signal the test that the scan is in-flight, then block until context cancelled.
			scanStartedOnce.Do(func() { close(scanStarted) })
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/api/graphql" {
			fmt.Fprint(w, `{"data":{}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	src := &GitHub{
		BaseURL:   strings.TrimRight(server.URL, "/") + "/api/v3/",
		URL:       "https://github.example.com/owner",
		Token:     "tok",
		Resources: GitHubResourceSet{GitHubResourceTypeReleases: true},
	}

	yield := func(_ Fragment, _ error) error {
		mu.Lock()
		if done {
			yieldAfterDone = true
		}
		mu.Unlock()
		return nil
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- src.Fragments(t.Context(), yield)
	}()

	// Wait for repo0's scan to reach the releases API (scan is in-flight).
	<-scanStarted

	// Now unblock the second repo-list page — this triggers the enum error.
	close(badRepoReady)

	// Wait for Fragments to return.
	err := <-errCh
	// Mark done so any post-return yield calls are detectable.
	mu.Lock()
	done = true
	mu.Unlock()

	require.Error(t, err, "Fragments should return the enum error")

	// Give any potential leaked goroutines time to fire.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	leaked := yieldAfterDone
	mu.Unlock()
	require.False(t, leaked, "yield was called after Fragments returned — in-flight scans were not properly awaited (A3 regression)")
}

// TestGitHubResourceSet_HasAnyIssueOrPR exercises the helper added in C4.
func TestGitHubResourceSet_HasAnyIssueOrPR(t *testing.T) {
	t.Parallel()

	require.False(t, GitHubResourceSet{}.HasAnyIssueOrPR())
	require.True(t, GitHubResourceSet{GitHubResourceTypeIssues: true}.HasAnyIssueOrPR())
	require.True(t, GitHubResourceSet{GitHubResourceTypePRs: true}.HasAnyIssueOrPR())
	require.True(t, GitHubResourceSet{GitHubResourceTypeIssueComments: true}.HasAnyIssueOrPR())
	require.True(t, GitHubResourceSet{GitHubResourceTypePRComments: true}.HasAnyIssueOrPR())
	require.False(t, GitHubResourceSet{GitHubResourceTypeRepos: true}.HasAnyIssueOrPR())
}

func Test_ParseGitHubURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		want    *ParsedGitHubURL
		wantErr bool
	}{
		{
			name: "owner",
			url:  "https://github.com/betterleaks",
			want: &ParsedGitHubURL{Owner: "betterleaks", Resource: "owner", Host: "github.com"},
		},
		{
			name: "owner trailing slash",
			url:  "https://github.com/betterleaks/",
			want: &ParsedGitHubURL{Owner: "betterleaks", Resource: "owner", Host: "github.com"},
		},
		{
			name: "repo",
			url:  "https://github.com/owner/repo",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "repo", Host: "github.com"},
		},
		{
			name: "repo trailing slash",
			url:  "https://github.com/owner/repo/",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "repo", Host: "github.com"},
		},
		{
			name: "issue",
			url:  "https://github.com/owner/repo/issues/123",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "issue", ID: "123", Host: "github.com"},
		},
		{
			name: "pr",
			url:  "https://github.com/owner/repo/pull/42",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "pr", ID: "42", Host: "github.com"},
		},
		{
			name: "discussion",
			url:  "https://github.com/owner/repo/discussions/7",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "discussion", ID: "7", Host: "github.com"},
		},
		{
			name: "release",
			url:  "https://github.com/owner/repo/releases/tag/v1.0.0",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "release", ID: "v1.0.0", Host: "github.com"},
		},
		{
			name: "actions run",
			url:  "https://github.com/owner/repo/actions/runs/9876543210",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "actions_run", ID: "9876543210", Host: "github.com"},
		},
		{
			name: "gist",
			url:  "https://gist.github.com/user/abc123def456",
			want: &ParsedGitHubURL{Owner: "user", Repo: "", Resource: "gist", ID: "abc123def456", Host: "gist.github.com"},
		},
		{
			name: "trailing slash on resource",
			url:  "https://github.com/owner/repo/issues/1/",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "issue", ID: "1", Host: "github.com"},
		},
		{
			name: "GHE owner",
			url:  "https://github.example.com/myorg",
			want: &ParsedGitHubURL{Owner: "myorg", Resource: "owner", Host: "github.example.com"},
		},
		{
			name: "GHE repo",
			url:  "https://github.example.com/owner/repo",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "repo", Host: "github.example.com"},
		},
		{
			name: "GHE issue",
			url:  "https://github.example.com/owner/repo/issues/55",
			want: &ParsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "issue", ID: "55", Host: "github.example.com"},
		},
		{
			name: "GHE gist",
			url:  "https://gist.github.example.com/user/deadbeef",
			want: &ParsedGitHubURL{Owner: "user", Repo: "", Resource: "gist", ID: "deadbeef", Host: "gist.github.example.com"},
		},
		// Error cases
		{
			name:    "no scheme",
			url:     "github.com/owner/repo/issues/1",
			wantErr: true,
		},
		{
			name:    "empty path",
			url:     "https://github.com/",
			wantErr: true,
		},
		{
			name:    "unsupported type",
			url:     "https://github.com/owner/repo/commits/abc",
			wantErr: true,
		},
		{
			name:    "release without tag",
			url:     "https://github.com/owner/repo/releases/latest",
			wantErr: true,
		},
		{
			name:    "actions without runs",
			url:     "https://github.com/owner/repo/actions/workflows/ci.yml",
			wantErr: true,
		},
		{
			name:    "gist missing id",
			url:     "https://gist.github.com/user",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseGitHubURL(tc.url)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGitHub_Validate_fromIncludeExclude(t *testing.T) {
	t.Parallel()

	src := &GitHub{
		URL:     "https://github.com/owner/repo",
		Token:   "tok",
		Include: []string{"repos", "issues", "releases"},
		Exclude: []string{"repos"},
	}
	require.NoError(t, src.Validate())

	require.False(t, src.Resources.Has(GitHubResourceTypeRepos))
	require.True(t, src.Resources.Has(GitHubResourceTypeIssues))
	require.True(t, src.Resources.Has(GitHubResourceTypeReleases))
	require.True(t, src.Resources.Has(GitHubResourceTypeReleaseAssets), "release-assets auto-included")
}

func TestGitHub_Validate_skipsWhenResourcesAlreadySet(t *testing.T) {
	t.Parallel()

	existing := GitHubResourceSet{GitHubResourceTypePRs: true}
	src := &GitHub{
		URL:       "https://github.com/owner/repo",
		Token:     "tok",
		Include:   []string{"issues"},
		Resources: existing,
	}
	require.NoError(t, src.Validate())
	require.True(t, src.Resources.Has(GitHubResourceTypePRs), "programmatic set preserved")
	require.False(t, src.Resources.Has(GitHubResourceTypeIssues), "Include ignored when Resources pre-set")
}

func TestGitHub_Validate_ownerDefaultsToRepos(t *testing.T) {
	t.Parallel()

	src := &GitHub{
		URL:   "https://github.com/myorg",
		Token: "tok",
	}
	require.NoError(t, src.Validate())
	require.True(t, src.Resources.Has(GitHubResourceTypeRepos))
}

func TestGitHub_Validate_unknownTypeErrors(t *testing.T) {
	t.Parallel()

	src := &GitHub{
		URL:     "https://github.com/owner/repo",
		Token:   "tok",
		Include: []string{"bogus"},
	}
	require.Error(t, src.Validate())
}

func TestGitHub_Validate_noTargetErrors(t *testing.T) {
	t.Parallel()

	src := &GitHub{Token: "tok"}
	require.ErrorContains(t, src.Validate(), "target URL is required")
}

func TestGitHub_Validate_resourceURLNeedsToken(t *testing.T) {
	t.Parallel()

	src := &GitHub{URL: "https://github.com/owner/repo/issues/1"}
	require.ErrorContains(t, src.Validate(), "token is required")
}

func TestGitHub_Validate_ownerURLNeedsToken(t *testing.T) {
	t.Parallel()

	src := &GitHub{URL: "https://github.com/myorg"}
	require.ErrorContains(t, src.Validate(), "token is required")
}

func TestGitHub_Validate_repoWithOnlyReposNoTokenOK(t *testing.T) {
	t.Parallel()

	src := &GitHub{URL: "https://github.com/owner/repo"}
	require.NoError(t, src.Validate())
	require.True(t, src.Resources.Has(GitHubResourceTypeRepos))
}

func TestGitHub_Validate_repoWithAPIResourceNeedsToken(t *testing.T) {
	t.Parallel()

	src := &GitHub{
		URL:     "https://github.com/owner/repo",
		Include: []string{"issues"},
	}
	require.ErrorContains(t, src.Validate(), "token is required")
}

func TestGitHub_Validate_repoWithTokenAndAPIResourceOK(t *testing.T) {
	t.Parallel()

	src := &GitHub{
		URL:     "https://github.com/owner/repo",
		Token:   "tok",
		Include: []string{"issues"},
	}
	require.NoError(t, src.Validate())
	require.True(t, src.Resources.Has(GitHubResourceTypeIssues))
	require.True(t, src.Resources.Has(GitHubResourceTypeRepos), "repos included by default for repo URL")
}
