//nolint:exhaustruct // Test fixtures specify only the fields relevant to each scenario.
package scm

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/stretchr/testify/require"
)

func TestSanitizeOutput(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		token   string
		notWant []string // none of these substrings should appear in output
		want    string   // optional: exact expected output
	}{
		{
			name:    "redacts raw token",
			text:    "fatal: could not auth using ghp_secrettoken",
			token:   "ghp_secrettoken",
			notWant: []string{"ghp_secrettoken"},
		},
		{
			name:  "redacts URL userinfo even if token absent",
			text:  "fatal: cloning https://x-access-token:ghp_secret@github.com/foo/bar.git failed",
			token: "",
			want:  "fatal: cloning https://***@github.com/foo/bar.git failed",
		},
		{
			name:    "redacts URL userinfo when token also matches",
			text:    "cloning https://x-access-token:ghp_secret@github.com/foo/bar.git",
			token:   "ghp_secret",
			notWant: []string{"ghp_secret", "x-access-token:"},
		},
		{
			name:  "empty text",
			text:  "",
			token: "ghp_secret",
			want:  "",
		},
		{
			name:  "no token, no userinfo",
			text:  "fatal: not a git repository",
			token: "",
			want:  "fatal: not a git repository",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeOutput(tc.text, tc.token)
			for _, bad := range tc.notWant {
				if strings.Contains(got, bad) {
					t.Errorf("SanitizeOutput leaked %q in %q", bad, got)
				}
			}
			if tc.want != "" && got != tc.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCloneTransportBoundary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("unexpected credentials on anonymous request")
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	for _, remote := range []string{"ssh://git@example.test/repo", "file:///tmp/repo", "git@example.test:repo", server.URL + "/repo?token=secret", server.URL + "/repo?", "http://user:secret@" + strings.TrimPrefix(server.URL, "http://") + "/repo"} {
		err := CloneAuthed(t.Context(), remote, "", filepath.Join(t.TempDir(), "repo"), CloneOptions{})
		if err == nil || !strings.Contains(err.Error(), "HTTP(S) URL") {
			t.Fatalf("unexpected URL validation result for %q: %v", remote, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("URL credentials leaked: %v", err)
		}
	}
	if err := CloneAuthed(t.Context(), server.URL+"/repo", "secret", filepath.Join(t.TempDir(), "repo"), CloneOptions{}); err == nil || !strings.Contains(err.Error(), "require HTTPS") {
		t.Fatalf("expected insecure token rejection, got %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("rejected clone made a network request")
	}
	if err := CloneAuthed(t.Context(), server.URL+"/repo", "", filepath.Join(t.TempDir(), "repo"), CloneOptions{}); err == nil {
		t.Fatal("expected missing repository error")
	}
	if requests.Load() == 0 {
		t.Fatal("clone did not use HTTP with an empty PATH")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := CloneAuthed(ctx, server.URL+"/repo", "", filepath.Join(t.TempDir(), "repo"), CloneOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestCloneRedirectCredentials(t *testing.T) {
	// Exercise CloneAuthed, including go-git's transport, rather than testing
	// an isolated redirect callback. All servers use httptest's TLS certificate.
	for _, mode := range []string{"downgrade", "other-origin", "same-origin"} {
		t.Run(mode, func(t *testing.T) {
			var targetRequests, authenticated atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetRequests.Add(1)
				if r.Header.Get("Authorization") != "" {
					t.Error("credentials reached another origin")
				}
				http.NotFound(w, r)
			})
			var target *httptest.Server
			if mode == "downgrade" {
				target = httptest.NewServer(handler)
			} else {
				target = httptest.NewTLSServer(handler)
			}
			defer target.Close()
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, token, ok := r.BasicAuth()
				if !ok || user != "x-access-token" || token != "TEST_TOKEN" {
					t.Error("missing credentials at repository origin")
				}
				authenticated.Add(1)
				if strings.HasPrefix(r.URL.Path, "/redirected/") {
					http.NotFound(w, r)
					return
				}
				location := target.URL + "/redirected/info/refs?service=git-upload-pack"
				if mode == "same-origin" {
					location = "/redirected/info/refs?service=git-upload-pack"
				}
				http.Redirect(w, r, location, http.StatusFound)
			}))
			defer origin.Close()
			previous := http.DefaultTransport
			http.DefaultTransport = origin.Client().Transport
			t.Cleanup(func() { http.DefaultTransport = previous })
			err := CloneAuthed(t.Context(), origin.URL+"/repo", "TEST_TOKEN", filepath.Join(t.TempDir(), "repo"), CloneOptions{})
			if err == nil || strings.Contains(err.Error(), "TEST_TOKEN") {
				t.Fatalf("expected sanitized clone failure: %v", err)
			}
			if mode == "downgrade" && targetRequests.Load() != 0 {
				t.Fatal("HTTPS downgrade was followed")
			}
			if mode == "other-origin" && targetRequests.Load() == 0 {
				t.Fatal("cross-origin redirect was not exercised")
			}
			if mode == "same-origin" && authenticated.Load() < 2 {
				t.Fatal("same-origin redirect was not exercised")
			}
		})
	}
}

// Git serves the fixture; the clone under test still uses go-git's HTTP transport.
func cloneTestRemote(t *testing.T, tlsHTTP2 bool) (string, func(string, ...string) string) {
	t.Helper()
	binary, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git fixture generator unavailable")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo.git")
	require.NoError(t, os.Mkdir(repo, 0o755))
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.test",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.test")
	run := func(input string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), binary, append([]string{"-C", repo}, args...)...)
		cmd.Env, cmd.Stdin = env, strings.NewReader(input)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
		return strings.TrimSpace(string(out))
	}
	run("", "init", "--bare", "--initial-branch=trunk")
	server := httptest.NewUnstartedServer(&cgi.Handler{Path: binary, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1"}})
	if tlsHTTP2 {
		server.EnableHTTP2 = true
		server.StartTLS()
		previous := http.DefaultTransport
		http.DefaultTransport = server.Client().Transport
		t.Cleanup(func() { http.DefaultTransport = previous })
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server.URL + "/repo.git", run
}

func TestCloneRequiresEmptyDestination(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()
	dest := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dest, "HEAD"), []byte("ref: refs/pull/1/head\n"), 0o600))
	err := CloneAuthed(t.Context(), server.URL+"/repo", "", dest, CloneOptions{})
	require.ErrorContains(t, err, "not empty")
	require.Zero(t, requests.Load(), "a rejected destination must not reach the network")
}

// Hosts such as GitHub accept HTTP/2 when a client offers it. The clone client
// speaks only HTTP/1.1, so it must not offer h2 during the TLS handshake.
func TestCloneFromHTTP2Server(t *testing.T) {
	remote, run := cloneTestRemote(t, true)
	tree := run("", "mktree")
	commit := run("", "commit-tree", tree, "-m", "root")
	run("", "update-ref", "refs/heads/trunk", commit)
	dest := filepath.Join(t.TempDir(), "clone")
	require.NoError(t, CloneAuthed(t.Context(), remote, "", dest, CloneOptions{}))
	repo, err := git.PlainOpen(dest)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	_, err = repo.CommitObject(plumbing.NewHash(commit))
	require.NoError(t, err)
}

func TestCloneRefSelection(t *testing.T) {
	remote, run := cloneTestRemote(t, false)
	commit := func(name, parent string) (plumbing.Hash, plumbing.Hash) {
		blob := run(name+"\n", "hash-object", "-w", "--stdin")
		tree := run("100644 blob "+blob+"\tcontent.txt\n", "mktree")
		args := []string{"commit-tree", tree, "-m", name}
		if parent != "" {
			args = append(args, "-p", parent)
		}
		return plumbing.NewHash(run("", args...)), plumbing.NewHash(blob)
	}
	root, _ := commit("root", "")
	main, _ := commit("main", root.String())
	side, _ := commit("side", root.String())
	tagOnly, _ := commit("tag only", root.String())
	run("", "update-ref", "refs/heads/trunk", main.String())
	run("", "update-ref", "refs/heads/side", side.String())
	run("", "tag", "lightweight", tagOnly.String())
	run("", "tag", "-a", "annotated", "-m", "tag message", tagOnly.String())
	run("", "notes", "add", "-m", "note content", main.String())
	wanted := map[plumbing.ReferenceName]plumbing.Hash{
		"refs/heads/trunk": main, "refs/heads/side": side,
		"refs/tags/lightweight": tagOnly,
		"refs/tags/annotated":   plumbing.NewHash(run("", "rev-parse", "refs/tags/annotated")),
		"refs/notes/commits":    plumbing.NewHash(run("", "rev-parse", "refs/notes/commits")),
	}
	additional := map[plumbing.ReferenceName]plumbing.Hash{}
	blobs := map[plumbing.ReferenceName]plumbing.Hash{}
	for _, name := range []string{
		"refs/pull/1/head", "refs/pull/2/head", "refs/pull/1/merge", "refs/merge-requests/1/head",
		"refs/pipelines/1", "refs/environments/1", "refs/changes/01/1/1",
		"refs/users/01/1", "refs/cache-automerge/01/1", "refs/pr/1",
		"refs/remotes/upstream/main", "refs/custom/private", "refs/custom/hidden",
	} {
		id, blob := commit(name, main.String())
		run("", "update-ref", name, id.String())
		additional[plumbing.ReferenceName(name)] = id
		blobs[plumbing.ReferenceName(name)] = blob
	}
	run("", "config", "uploadpack.hideRefs", "refs/custom/hidden")

	for _, tc := range []struct {
		name    string
		options CloneOptions
		extra   []plumbing.ReferenceName
	}{
		{name: "default"},
		{name: "one PR", options: CloneOptions{Refs: []string{"refs/pull/1/head"}}, extra: []plumbing.ReferenceName{"refs/pull/1/head"}},
		{name: "PR heads", options: CloneOptions{Refs: []string{"refs/pull/*/head"}}, extra: []plumbing.ReferenceName{"refs/pull/1/head", "refs/pull/2/head"}},
		{name: "repeated and overlapping", options: CloneOptions{Refs: []string{"refs/pull/*/head", "refs/pull/1/head", "refs/pull/1/head", "refs/custom/private"}}, extra: []plumbing.ReferenceName{"refs/pull/1/head", "refs/pull/2/head", "refs/custom/private"}},
		{name: "unmatched pattern", options: CloneOptions{Refs: []string{"refs/missing/*"}}},
		{name: "all refs", options: CloneOptions{AllRefs: true}},
		{name: "all subsumes additional", options: CloneOptions{AllRefs: true, Refs: []string{"refs/pull/1/head"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "clone")
			require.NoError(t, CloneAuthed(t.Context(), remote, "", dest, tc.options))
			repo, err := git.PlainOpen(dest)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repo.Close()) })
			_, err = repo.Worktree()
			require.ErrorIs(t, err, git.ErrIsBareRepository)
			require.NoFileExists(t, filepath.Join(dest, "content.txt"))
			refs, err := repo.References()
			require.NoError(t, err)
			got := map[plumbing.ReferenceName]plumbing.Hash{}
			require.NoError(t, refs.ForEach(func(ref *plumbing.Reference) error {
				if ref.Name() != plumbing.HEAD {
					got[ref.Name()] = ref.Hash()
				}
				return nil
			}))
			want := maps.Clone(wanted)
			if tc.options.AllRefs {
				maps.Copy(want, additional)
				delete(want, "refs/custom/hidden")
			}
			for _, name := range tc.extra {
				want[name] = additional[name]
			}
			require.Equal(t, want, got)
			head, err := repo.Reference(plumbing.HEAD, false)
			require.NoError(t, err)
			require.Equal(t, plumbing.ReferenceName("refs/heads/trunk"), head.Target())
			_, err = repo.CommitObject(root)
			require.NoError(t, err, "full branch history must be fetched")
			_, err = repo.CommitObject(tagOnly)
			require.NoError(t, err, "history reachable only from tags must be fetched")
			for name, id := range additional {
				for _, object := range []plumbing.Hash{id, blobs[name]} {
					if _, selected := want[name]; selected {
						require.NoError(t, repo.Storer.HasEncodedObject(object), "selected object %s", name)
					} else {
						require.ErrorIs(t, repo.Storer.HasEncodedObject(object), plumbing.ErrObjectNotFound,
							"unselected object %s must not be downloaded", name)
					}
				}
			}
		})
	}
}

func TestCloneInvalidRefs(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	for _, ref := range []string{"", "main", "HEAD", strings.Repeat("a", 40), "+refs/pull/1/head", "refs/pull/1/head:refs/heads/pr", "refs/../HEAD", "refs//head", "refs/head/", "refs/a.lock", "refs/.hidden", "refs/a..b", "refs/a@{1}", "refs/a\\b", "refs/a b", "refs/a\n", "refs/pull/?/head", "refs/pull/[12]/head", "refs/*/*"} {
		t.Run(ref, func(t *testing.T) {
			// AllRefs must not bypass validation of supplied values.
			for _, all := range []bool{false, true} {
				dest := filepath.Join(t.TempDir(), "clone")
				err := CloneAuthed(t.Context(), server.URL, "", dest, CloneOptions{Refs: []string{ref}, AllRefs: all})
				require.ErrorContains(t, err, "invalid clone ref")
				require.NoDirExists(t, dest)
			}
		})
	}
	require.Zero(t, requests.Load(), "invalid refs must be rejected before network access")
}

func TestCloneMissingExactRef(t *testing.T) {
	remote, run := cloneTestRemote(t, false)
	for _, empty := range []bool{true, false} {
		if !empty {
			tree := run("", "mktree")
			id := run("", "commit-tree", tree, "-m", "root")
			run("", "update-ref", "refs/heads/trunk", id)
		}
		called := false
		err := CloneToTempDir(t.Context(), remote, "", "", CloneOptions{Refs: []string{"refs/pull/404/head"}, AllRefs: false}, func(string) error {
			called = true
			return nil
		})
		require.ErrorContains(t, err, "refs/pull/404/head")
		require.False(t, called, "a missing exact ref must not silently scan default history")
	}
}

func TestClonePublishedRefsWithoutBranches(t *testing.T) {
	for _, kind := range []string{"empty", "tag-only", "review-only", "detached-published", "detached-review"} {
		t.Run(kind, func(t *testing.T) {
			remote, run := cloneTestRemote(t, false)
			var id plumbing.Hash
			if kind != "empty" {
				tree := run("", "mktree")
				id = plumbing.NewHash(run("", "commit-tree", tree, "-m", kind))
				ref := "refs/tags/v1"
				if kind == "review-only" || kind == "detached-review" {
					ref = "refs/pull/1/head"
				}
				run("", "update-ref", ref, id.String())
				if strings.HasPrefix(kind, "detached-") {
					run("", "update-ref", "--no-deref", "HEAD", id.String())
				}
			}
			dest := filepath.Join(t.TempDir(), "clone")
			require.NoError(t, CloneAuthed(t.Context(), remote, "", dest, CloneOptions{}))
			repo, err := git.PlainOpen(dest)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repo.Close()) })
			if kind == "tag-only" || kind == "detached-published" {
				_, err := repo.CommitObject(id)
				require.NoError(t, err)
			} else if kind == "review-only" || kind == "detached-review" {
				require.ErrorIs(t, repo.Storer.HasEncodedObject(id), plumbing.ErrObjectNotFound)
			}
			if kind == "detached-published" {
				head, err := repo.Head()
				require.NoError(t, err)
				require.Equal(t, id, head.Hash())
			}
		})
	}
}
