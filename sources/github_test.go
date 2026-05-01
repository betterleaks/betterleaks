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
	"strings"
	"testing"
	"time"

	"github.com/fatih/semgroup"
	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/celenv"
)

func TestGitHub_scanRepo_prefilterSkipsRepoByResourceAttrs(t *testing.T) {
	t.Parallel()

	repoPath := createGitHubTestRepo(t)
	skip := compileGitHubPrefilter(t, `attributes[?"resource"].orValue("") == "github.repository" && attributes[?"github.repo"].orValue("") == "repo"`)

	src := &GitHub{ShouldSkip: skip, Sema: semgroup.NewGroup(t.Context(), 4)}
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

	src := &GitHub{ShouldSkip: skip, Sema: semgroup.NewGroup(t.Context(), 4)}
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

	src := &GitHub{ShouldSkip: skip, Sema: semgroup.NewGroup(t.Context(), 4)}
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
		SkipRepoGit: true,
		Sema:        semgroup.NewGroup(t.Context(), 4),
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
		BaseURL: strings.TrimRight(server.URL, "/") + "/api/v3/",
		URL:     "https://gist.github.example.com/user/abc123def456",
	}
	client := src.newClient(t.Context())

	var fragments []Fragment
	require.NotPanics(t, func() {
		err := src.scanURL(t.Context(), client, func(fragment Fragment, err error) error {
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

	src := &GitHub{ScanIssues: true, ScanIssueComments: true}
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

func TestGitHub_emitPRAndComments_stampsPRAndReviewThreadAttrs(t *testing.T) {
	t.Parallel()

	src := &GitHub{ScanPRs: true, ScanPRComments: true}
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

	src := &GitHub{ScanDiscussions: true}
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

	src := &GitHub{ScanReleaseAssets: false}
	var fragments []Fragment
	err := src.emitRelease(t.Context(), nil, "owner", "repo", rel, func(fragment Fragment, err error) error {
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
		ScanReleaseAssets: false,
		ShouldSkip:        compileGitHubPrefilter(t, `attributes[?"resource"].orValue("") == "github.release" && attributes[?"github.release.tag"].orValue("") == "v1.0.0"`),
	}

	called := false
	err := src.emitRelease(t.Context(), nil, "owner", "repo", rel, func(fragment Fragment, err error) error {
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
	var fragments []Fragment
	err = src.downloadAndScanZip(t.Context(), zipURL, run, "actions/logs", func(fragment Fragment, err error) error {
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
