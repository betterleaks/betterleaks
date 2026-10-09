package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

// The history holds additions, modifications, a multi-paragraph message with
// trailing blank lines, a rename, a binary blob, a deletion, a branch with a
// merge, and a line removed and re-added. The objects end up in one pack.
func packTestRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) string { return runGitTestCommand(t, repo, args...) }
	write := func(name, content string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600))
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test User")
	run("remote", "add", "origin", "git@github.com:example/pack-test.git")

	write("app/config.py", "DEBUG = True\nAPI_KEY = 'first-key-0001'\n")
	write("README.md", "# pack test\n")
	run("add", ".")
	run("commit", "--quiet", "-m", "initial import\n\nAdds the configuration module.\n\n\n")

	write("app/config.py", "DEBUG = False\nAPI_KEY = 'first-key-0001'\nTOKEN = 'second-token-0002'\n")
	run("add", ".")
	run("commit", "--quiet", "-m", "flip debug and add token")

	run("mv", "app/config.py", "app/settings.py")
	run("commit", "--quiet", "-m", "rename config")

	write("blob.bin", "\x00\x01\x02binary\x00payload")
	run("add", ".")
	run("commit", "--quiet", "-m", "add binary")

	run("checkout", "--quiet", "-b", "feature")
	write("feature.txt", "FEATURE_SECRET = 'feature-only-0003'\n")
	run("add", ".")
	run("commit", "--quiet", "-m", "feature work")
	run("checkout", "--quiet", "main")
	write("README.md", "# pack test\n\nMain branch line.\n")
	run("add", ".")
	run("commit", "--quiet", "-m", "readme on main")
	run("merge", "--quiet", "--no-ff", "--no-edit", "feature")

	run("rm", "--quiet", "README.md")
	run("commit", "--quiet", "-m", "drop readme")

	write("app/settings.py", "DEBUG = False\nTOKEN = 'second-token-0002'\n")
	run("add", ".")
	run("commit", "--quiet", "-m", "remove api key")
	write("app/settings.py", "DEBUG = False\nAPI_KEY = 'first-key-0001'\nTOKEN = 'second-token-0002'\n")
	run("add", ".")
	run("commit", "--quiet", "-m", "re-add api key")

	run("repack", "-a", "-d", "--quiet")
	run("prune-packed", "--quiet")
	return repo
}

type packFragment struct {
	SHA, Path, Raw string
	StartLine      int
	Attrs          map[string]string
}

func collectFragments(t *testing.T, src *Git) []packFragment {
	t.Helper()
	var (
		mu  sync.Mutex
		out []packFragment
	)
	require.NoError(t, src.Fragments(context.Background(), func(f Fragment, err error) error {
		if err != nil {
			return err
		}
		mu.Lock()
		out = append(out, packFragment{SHA: f.Attr(AttrGitSHA), Path: f.Attr(AttrPath), Raw: f.Raw, StartLine: f.StartLine, Attrs: f.Attributes})
		mu.Unlock()
		return nil
	}))
	// git log renders a pure rename as a header with no hunks, which the
	// patch reader yields as an empty fragment; the pack engine yields a
	// fragment for added lines only.
	out = slices.DeleteFunc(out, func(f packFragment) bool { return f.Raw == "" })
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SHA != b.SHA {
			return a.SHA < b.SHA
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.Raw < b.Raw
	})
	return out
}

func TestGitPackEngineMatchesGitEngine(t *testing.T) {
	repo := packTestRepo(t)
	want := collectFragments(t, &Git{RepoPath: repo, Engine: GitEngineGit, RemoteURL: "https://github.com/example/pack-test", Platform: scm.GitHubPlatform})
	got := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack, RemoteURL: "https://github.com/example/pack-test", Platform: scm.GitHubPlatform})
	require.NotEmpty(t, want)
	require.Equal(t, len(want), len(got))
	for i := range want {
		require.Equal(t, want[i].SHA, got[i].SHA, "fragment %d", i)
		require.Equal(t, want[i].Path, got[i].Path, "fragment %d", i)
		require.Equal(t, want[i].StartLine, got[i].StartLine, "fragment %d %s", i, want[i].Path)
		require.Equal(t, want[i].Raw, got[i].Raw, "fragment %d %s", i, want[i].Path)
		require.Equal(t, want[i].Attrs, got[i].Attrs, "fragment %d %s", i, want[i].Path)
	}
	for _, key := range []string{AttrGitSHA, AttrGitMessage, AttrGitAuthorName, AttrGitAuthorEmail, AttrGitDate, AttrGitRemoteURL, AttrGitPlatform, AttrResource, AttrPath} {
		require.Contains(t, got[0].Attrs, key)
	}
	require.Equal(t, ResourceGitPatchContent, got[0].Attrs[AttrResource])
}

func TestGitPackEngineDedupLines(t *testing.T) {
	repo := packTestRepo(t)
	count := func(frags []packFragment, needle string) int {
		n := 0
		for _, f := range frags {
			n += strings.Count(f.Raw, needle)
		}
		return n
	}
	plain := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack})
	dedup := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack, DedupLines: true})
	require.Equal(t, 2, count(plain, "first-key-0001"), "the plain scan reports the initial import and the re-add")
	require.Equal(t, 1, count(dedup, "first-key-0001"), "dedup reports the first introduction only")
	require.Equal(t, 2, count(plain, "feature-only-0003"), "the plain scan reports the feature commit and the merge's first-parent diff")
	require.Equal(t, 1, count(dedup, "feature-only-0003"), "dedup reports the feature commit only")
	plainKeys := map[string]bool{}
	for _, f := range plain {
		plainKeys[f.SHA+"\x00"+f.Path] = true
	}
	for _, f := range dedup {
		require.True(t, plainKeys[f.SHA+"\x00"+f.Path], "%s %s", f.SHA, f.Path)
	}
}

func TestGitPackEngineArchives(t *testing.T) {
	repo := newGitTestRepo(t, 0)
	var data bytes.Buffer
	archive := zip.NewWriter(&data)
	entry, err := archive.Create("inner.txt")
	require.NoError(t, err)
	_, err = io.WriteString(entry, "synthetic archive example\n")
	require.NoError(t, err)
	require.NoError(t, archive.Close())
	require.NoError(t, os.WriteFile(filepath.Join(repo, "archive.zip"), data.Bytes(), 0o600))
	runGitTestCommand(t, repo, "add", ".")
	runGitTestCommand(t, repo, "commit", "-qm", "archive")
	for _, depth := range []int{0, 1} {
		frags := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack, MaxArchiveDepth: depth})
		if depth == 0 {
			require.Empty(t, frags)
			continue
		}
		require.Len(t, frags, 1)
		require.Equal(t, "synthetic archive example\n", frags[0].Raw)
		require.Equal(t, "archive.zip"+InnerPathSeparator+"inner.txt", frags[0].Path)
		require.Len(t, frags[0].SHA, 40)
		require.Equal(t, "archive", frags[0].Attrs[AttrGitMessage])
	}
}

func TestGitPackEngineHonorsShouldSkip(t *testing.T) {
	repo := packTestRepo(t)
	src := &Git{RepoPath: repo, Engine: GitEnginePack, Prefilter: func(attrs map[string]string) bool {
		return strings.HasPrefix(attrs[AttrPath], "app/")
	}}
	frags := collectFragments(t, src)
	require.NotEmpty(t, frags)
	for _, f := range frags {
		require.False(t, strings.HasPrefix(f.Path, "app/"), f.Path)
	}
}

func TestGitPackEngineRunsWithoutGit(t *testing.T) {
	repo := packTestRepo(t)
	want := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack})
	t.Setenv("PATH", t.TempDir())
	got := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack})
	require.Equal(t, want, got)
}

func TestGitPackEngineBareAndWorktree(t *testing.T) {
	repo := packTestRepo(t)
	bare := filepath.Join(t.TempDir(), "bare.git")
	runGitTestCommand(t, repo, "clone", "--quiet", "--bare", repo, bare)
	linked := filepath.Join(t.TempDir(), "linked")
	runGitTestCommand(t, repo, "worktree", "add", "--quiet", "--detach", linked)

	want := collectFragments(t, &Git{RepoPath: repo, Engine: GitEnginePack})
	for _, path := range []string{filepath.Join(repo, ".git"), bare, linked} {
		got := collectFragments(t, &Git{RepoPath: path, Engine: GitEnginePack})
		require.Equal(t, want, got, path)
	}
}

func TestResolveGitDir(t *testing.T) {
	repo := packTestRepo(t)
	dir, err := resolveGitDir(repo)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(repo, ".git"), dir)

	dir, err = resolveGitDir(filepath.Join(repo, ".git"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(repo, ".git"), dir)

	linked := filepath.Join(t.TempDir(), "linked")
	runGitTestCommand(t, repo, "worktree", "add", "--quiet", "--detach", linked)
	dir, err = resolveGitDir(linked)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(repo, ".git"), dir, "a linked work tree resolves to the shared repository")

	_, err = resolveGitDir(t.TempDir())
	require.ErrorContains(t, err, "not a git repository")
}

func TestRemoteURLFromConfig(t *testing.T) {
	repo := packTestRepo(t)
	url, ok := remoteURLFromConfig(repo)
	require.True(t, ok)
	require.Equal(t, "git@github.com:example/pack-test.git", url)

	runGitTestCommand(t, repo, "remote", "add", "upstream", "https://example.com/upstream.git")
	url, ok = remoteURLFromConfig(repo)
	require.True(t, ok)
	require.Equal(t, "git@github.com:example/pack-test.git", url, "origin wins over other remotes")
	runGitTestCommand(t, repo, "remote", "remove", "origin")
	url, ok = remoteURLFromConfig(repo)
	require.True(t, ok)
	require.Equal(t, "https://example.com/upstream.git", url)
	runGitTestCommand(t, repo, "remote", "remove", "upstream")
	_, ok = remoteURLFromConfig(repo)
	require.False(t, ok)

	runGitTestCommand(t, repo, "remote", "add", "origin", "https://example.com/origin.git")
	linked := filepath.Join(t.TempDir(), "linked")
	runGitTestCommand(t, repo, "worktree", "add", "--quiet", "--detach", linked)
	url, ok = remoteURLFromConfig(linked)
	require.True(t, ok)
	require.Equal(t, "https://example.com/origin.git", url, "a linked work tree reads the shared config")

	t.Setenv("PATH", t.TempDir())
	_, remote := ResolveRemote(context.Background(), scm.GitHubPlatform, repo)
	require.Equal(t, "https://example.com/origin", remote, "ResolveRemote runs without git")
}

func TestGitEngineValidation(t *testing.T) {
	require.NoError(t, (&Git{Engine: ""}).Validate())
	require.NoError(t, (&Git{Engine: GitEngineAuto}).Validate())
	require.NoError(t, (&Git{Engine: GitEngineGit}).Validate())
	require.NoError(t, (&Git{Engine: GitEnginePack}).Validate())
	require.ErrorContains(t, (&Git{Engine: "libgit"}).Validate(), `unknown git engine "libgit"`)

	require.True(t, (&Git{RepoPath: "."}).InProcess())
	require.False(t, (&Git{RepoPath: ".", LogOpts: "--since=1.week"}).InProcess())
	require.False(t, (&Git{RepoPath: ".", Include: []string{GitResourceTypeCommitMessages}}).InProcess())
	require.False(t, (&Git{RepoPath: ".", Mode: GitStaged}).InProcess())
	require.False(t, (&Git{RepoPath: ".", Engine: GitEngineGit}).InProcess())

	src := &Git{RepoPath: ".", Engine: GitEnginePack, LogOpts: "--since=1.week"}
	_, err := src.usePackEngine()
	require.ErrorContains(t, err, "--log-opts requires the git executable")
	err = src.Fragments(context.Background(), func(Fragment, error) error { return nil })
	require.ErrorContains(t, err, "--log-opts requires the git executable")
	_, err = (&Git{RepoPath: ".", Engine: GitEnginePack, Mode: GitWorkingTree}).usePackEngine()
	require.ErrorContains(t, err, "diff modes require the git executable")
}

func TestFormatMessageMatchesPatchHeader(t *testing.T) {
	cases := []string{
		"one line\n",
		"title\n\nbody line one\nbody line two\n",
		"title\n\n\n\nbody after blank run\n\n\n",
		"wrapped title\ncontinues here\n\nbody\n",
		"",
		"no trailing newline",
		"title\n\n    indented body\n    second\n",
	}
	for _, raw := range cases {
		header, err := gitdiff.ParsePatchHeader(fmt.Sprintf("commit 0123456789abcdef0123456789abcdef01234567\nAuthor: A <a@example.com>\nDate:   Mon Jan 2 15:04:05 2006 +0000\n\n%s", gitLogIndent(raw)))
		require.NoError(t, err, raw)
		require.Equal(t, header.Message(), gitdiff.FormatMessage(raw), "%q", raw)
	}
}

// gitLogIndent applies the four-space indent git log puts on message lines.
func gitLogIndent(raw string) string {
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "    " + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestPackObjectCacheBudget(t *testing.T) {
	repo := packTestRepo(t)
	gitDir := filepath.Join(repo, ".git")
	require.Equal(t, packObjectCacheMin, packObjectCacheBudget(gitDir), "a tiny pack gets the minimum")
	require.Equal(t, packObjectCacheMax, packObjectCacheBudget(t.TempDir()), "no pack directory: the maximum")

	big := filepath.Join(gitDir, "objects", "pack", "pack-synthetic.pack")
	require.NoError(t, os.WriteFile(big, make([]byte, 40<<20), 0o600))
	t.Cleanup(func() { os.Remove(big) })
	got := packObjectCacheBudget(gitDir)
	require.Greater(t, got, 80<<20, "twice the packed bytes")
	require.Less(t, got, packObjectCacheMax)
}

func TestJoinAddedLines(t *testing.T) {
	require.Equal(t, "", joinAddedLines(nil))
	require.Equal(t, "a\n", joinAddedLines([]string{"a"}))
	require.Equal(t, "a\n\nb\n", joinAddedLines([]string{"a", "", "b"}))
}
