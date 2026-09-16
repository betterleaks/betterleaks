package sources

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuto(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.MkdirAll("github.com/owner/repo/.git", 0o700))
	require.NoError(t, os.WriteFile("file.txt", []byte("local"), 0o600))
	for _, tc := range []struct {
		target string
		kind   Kind
	}{
		{".", FilesystemKind},
		{"file.txt", FilesystemKind},
		{"github.com/owner/repo", FilesystemKind},
		{"github.com/missing/repo", UnknownKind},
		{"missing", UnknownKind},
		{"ssh://git@example.com/repo", UnknownKind},
		{"git@example.com:repo", UnknownKind},
		{"ftp://example.com/file", UnknownKind},
		{"https://github.com/owner/repo", GitKind},
		{"https://github.com/owner", GitHubKind},
		{"https://github.com/owner/repo/issues/1", GitHubKind},
		{"https://github.com/owner/repo/pull/1/files", GitHubKind},
		{"https://github.com/owner/repo/discussions/1", GitHubKind},
		{"https://github.com/owner/repo/releases/tag/v1", GitHubKind},
		{"https://github.com/owner/repo/actions/runs/42", GitHubKind},
		{"https://gist.github.com/owner/123", GitHubKind},
		{"https://gitlab.com/group", GitLabKind},
		{"https://gitlab.com/group/repo/-/issues/1", GitLabKind},
		{"https://gitlab.com/group/subgroup/repo/-/merge_requests/1", GitLabKind},
		{"https://gitlab.com/group/repo/-/jobs/42/artifacts", GitLabKind},
		{"https://example.com/repo.git", GitKind},
		{"https://huggingface.co/owner/model", GitKind},
		{"https://huggingface.co/datasets/owner/data", GitKind},
		{"https://huggingface.co/spaces/owner/space", GitKind},
		{"https://huggingface.co/owner", HuggingFaceKind},
		{"https://huggingface.co/buckets/owner/data", HuggingFaceKind},
		{"hf://buckets/owner/data/prefix", HuggingFaceKind},
		{"hf://models/owner/model", UnknownKind},
		{"s3://bucket/prefix", S3Kind},
		{"https://bucket.s3.us-east-1.amazonaws.com/prefix", S3Kind},
		{"https://s3.us-east-1.amazonaws.com/bucket", S3Kind},
		{"https://account.r2.cloudflarestorage.com/bucket", S3Kind},
	} {
		t.Run(tc.target, func(t *testing.T) {
			client := &http.Client{Transport: autoRoundTrip(func(*http.Request) (*http.Response, error) {
				t.Fatal("unnecessary discovery request")
				return nil, nil
			})}
			kind, err := Auto(t.Context(), tc.target, WithAutoHTTPClient(client))
			require.Equal(t, tc.kind, kind)
			if tc.kind == UnknownKind {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	// Even a URL-shaped name is local if it exists.
	require.NoError(t, os.MkdirAll(filepath.FromSlash("https:/example.com/repo.git"), 0o700))
	kind, err := Auto(t.Context(), "https://example.com/repo.git")
	require.NoError(t, err)
	require.Equal(t, FilesystemKind, kind)
}

func TestAutoProviderContentURLs(t *testing.T) {
	for _, target := range []string{
		"https://huggingface.co/owner/model/resolve/main/config.json",
		"https://huggingface.co/datasets/owner/data/resolve/main/data.zip",
		"https://github.com/owner/repo/archive/refs/heads/main.zip",
		"https://gitlab.com/group/repo/-/raw/main/config.txt",
	} {
		client := &http.Client{Transport: autoRoundTrip(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
		kind, err := Auto(t.Context(), target, WithAutoHTTPClient(client))
		require.NoError(t, err)
		require.Equal(t, URLKind, kind, target)
	}
}

func gitPacket(body string) string { return fmt.Sprintf("%04x%s", len(body)+4, body) }

type autoRoundTrip func(*http.Request) (*http.Response, error)

func (f autoRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestAutoGitDiscovery(t *testing.T) {
	service := gitPacket("# service=git-upload-pack\n") + "0000"
	ref := gitPacket(strings.Repeat("a", 40) + " HEAD\x00multi_ack\n")
	v2 := gitPacket("version 2\n") + gitPacket("agent=fixture\n") + gitPacket("ls-refs=unborn\n") + "0000"
	for _, tc := range []struct {
		name              string
		status            int
		contentType, body string
		kind              Kind
	}{
		{"v0", 200, "application/x-git-upload-pack-advertisement", service + ref, GitKind},
		{"v1", 200, "application/x-git-upload-pack-advertisement", service + gitPacket("version 1\n") + ref, GitKind},
		{"v2", 200, "application/x-git-upload-pack-advertisement", v2, GitKind},
		{"v2 with service", 200, "application/x-git-upload-pack-advertisement", service + v2, GitKind},
		{"empty repo", 200, "application/x-git-upload-pack-advertisement", service + gitPacket(strings.Repeat("0", 40)+" capabilities^{}\x00multi_ack\n"), GitKind},
		{"html", 200, "text/html", "hello", URLKind},
		{"404", 404, "text/html", "missing", URLKind},
		{"gone", 410, "text/plain", "gone", URLKind},
		{"unauthorized", 401, "text/plain", "", UnknownKind},
		{"forbidden", 403, "text/plain", "", UnknownKind},
		{"rate limit", 429, "text/plain", "", UnknownKind},
		{"server error", 500, "text/plain", "", UnknownKind},
		{"malformed", 200, "application/x-git-upload-pack-advertisement", "hello", UnknownKind},
		{"oversized", 200, "application/x-git-upload-pack-advertisement", gitPacket("version 2\n") + strings.Repeat(gitPacket("agent="+strings.Repeat("x", 1000)+"\n"), 100), UnknownKind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/project/info/refs", r.URL.Path)
				require.Equal(t, "git-upload-pack", r.URL.Query().Get("service"))
				require.Equal(t, "version=2", r.Header.Get("Git-Protocol"))
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			kind, err := Auto(t.Context(), srv.URL+"/project/")
			require.Equal(t, tc.kind, kind)
			if tc.kind == UnknownKind {
				require.ErrorContains(t, err, "select git or url explicitly")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAutoGitCancellationAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/redirect") {
			http.Redirect(w, r, "/redirect", http.StatusFound)
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	kind, err := Auto(ctx, srv.URL+"/slow")
	require.Equal(t, UnknownKind, kind)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	kind, err = Auto(t.Context(), srv.URL+"/redirect")
	require.Equal(t, UnknownKind, kind)
	require.ErrorContains(t, err, "three redirects")
}

func TestAutoGitLabNamespaceAndClient(t *testing.T) {
	for _, isRepo := range []bool{true, false} {
		client := &http.Client{Transport: autoRoundTrip(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "https://gitlab.com/group/subgroup/info/refs?service=git-upload-pack", req.URL.String())
			resp := &http.Response{
				StatusCode: 404,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
			}
			if isRepo {
				resp.StatusCode = 200
				resp.Header.Set("Content-Type", "application/x-git-upload-pack-advertisement")
				resp.Body = io.NopCloser(strings.NewReader(gitPacket("version 2\n") + gitPacket("ls-refs\n") + "0000"))
			}
			return resp, nil
		})}
		kind, err := Auto(t.Context(), "https://gitlab.com/group/subgroup", WithAutoHTTPClient(client))
		require.NoError(t, err)
		if isRepo {
			require.Equal(t, GitKind, kind)
		} else {
			require.Equal(t, GitLabKind, kind)
		}
		require.Nil(t, client.CheckRedirect, "detection must not modify the caller's client")
	}
}

func TestAutoGitRedirectAndEscapedPath(t *testing.T) {
	var finalPath string
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, r.Header.Get("Authorization"), "do not forward userinfo credentials to another origin")
		finalPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = io.WriteString(w, gitPacket("version 2\n")+gitPacket("ls-refs\n")+"0000")
	}))
	defer final.Close()
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, password, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "password", password)
		require.Equal(t, "/project%2Frepo/info/refs", r.URL.EscapedPath())
		http.Redirect(w, r, final.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer initial.Close()
	target := strings.Replace(initial.URL, "://", "://user:password@", 1) + "/project%2Frepo?token=private-token#private-fragment"
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	kind, err := Auto(t.Context(), target, WithAutoLogger(logger))
	require.NoError(t, err)
	require.Equal(t, GitKind, kind)
	require.Equal(t, "/project%2Frepo/info/refs", finalPath)
	require.Contains(t, logs.String(), `"source":"git"`)
	require.Contains(t, logs.String(), "checking URL for a Git repository")
	for _, secret := range []string{"user:password", "private-token", "private-fragment"} {
		require.NotContains(t, logs.String(), secret)
	}
}
