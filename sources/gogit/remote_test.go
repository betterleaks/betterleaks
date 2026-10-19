//nolint:exhaustruct // Test fixtures specify only relevant fields.
package gogit

import (
	"fmt"
	"io"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/stretchr/testify/require"
)

func TestRemotePackScanParity(t *testing.T) {
	repo := newHistory(t)
	for revision := range 8 {
		text := strings.Repeat("shared content for delta compression\n", 1000) + fmt.Sprintf("TOKEN_%d\n", revision)
		require.NoError(t, os.WriteFile(filepath.Join(repo, "delta.txt"), []byte(text), 0600))
		gitFixture(t, repo, "add", "delta.txt")
		gitFixture(t, repo, "commit", "-qm", fmt.Sprintf("delta %d", revision))
	}
	gitFixture(t, repo, "repack", "-adf", "--window=20", "--depth=20")
	binary, err := exec.LookPath("git")
	require.NoError(t, err)
	// Git only serves the fixture; the client fetch and scan run in Go.
	server := httptest.NewServer(&cgi.Handler{Path: binary, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + repo, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1"}})
	t.Cleanup(server.Close)
	remote := server.URL + "/.git"
	t.Setenv("PATH", t.TempDir())
	type fragment struct {
		resource, commit, blob, path, raw string
		line                              int
	}
	observe := func(s *Source) []fragment {
		var out []fragment
		for _, f := range collect(t, s) {
			out = append(out, fragment{f.Attr(sources.AttrResource), f.Attr(sources.AttrGitSHA),
				f.Attr(sources.AttrGitBlobSHA), f.Attr(sources.AttrPath), f.Raw, f.StartLine})
		}
		return out
	}
	want := observe(&Source{RepoPath: repo})
	require.NotEmpty(t, want)
	require.ElementsMatch(t, want, observe(&Source{URL: remote}))
	err = (&Source{URL: remote, Revision: "refs/pull/123/head"}).Fragments(t.Context(), func(sources.Fragment, error) error {
		t.Fatal("an unavailable revision must fail before scanning")
		return nil
	})
	require.ErrorIs(t, err, plumbing.ErrReferenceNotFound)
	require.ErrorContains(t, err, "--clone-ref=refs/...")
	require.NoError(t, scm.CloneToTempDir(t.Context(), remote, "", "", scm.CloneOptions{}, func(path string) error {
		r, cleanup, err := (&Source{RepoPath: path}).open(t.Context())
		require.NoError(t, err)
		defer cleanup()
		store := r.Storer.(*objectStorage)
		require.Len(t, store.packs, 1, "the fetched reverse index enables the fast pack reader")
		p := store.packs[0]
		iter, err := p.index.Entries()
		require.NoError(t, err)
		defer iter.Close()
		deltas := 0
		for {
			e, err := iter.Next()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			record, err := store.inflate(p, int64(e.Offset), false)
			require.NoError(t, err)
			if record.kind.IsDelta() {
				deltas++
			}
		}
		require.Positive(t, deltas, "fixture must exercise delta resolution")
		require.ElementsMatch(t, want, observe(&Source{RepoPath: path}))
		return nil
	}))
}
