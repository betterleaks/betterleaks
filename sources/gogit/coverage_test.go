//nolint:exhaustruct // Test fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/gitfs"
	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/sources"
	format "github.com/go-git/go-git/v5/plumbing/format/config"
	"github.com/stretchr/testify/require"
)

func gitInput(t *testing.T, repo string, input []byte, args ...string) string {
	t.Helper()
	binary, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git fixture generator unavailable")
	}
	cmd := exec.Command(binary, append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}

func initRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	gitFixture(t, repo, "config", "user.name", "Coverage")
	gitFixture(t, repo, "config", "user.email", "coverage@example.test")
	return repo
}

func commitFile(t *testing.T, repo, name, content, message string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0600))
	gitFixture(t, repo, "add", "--", name)
	gitFixture(t, repo, "commit", "-qm", message)
	return gitFixture(t, repo, "rev-parse", "HEAD")
}

// A binary predecessor shares no lines with the new text, so all of it is new.
func TestBinaryToText(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "creds.env", "abc\x00def\n", "binary")
	commitFile(t, repo, "creds.env", "TOKEN_AFTER_BINARY\n", "text")
	fs := collect(t, &Source{RepoPath: repo})
	require.Equal(t, map[string]string{"TOKEN_AFTER_BINARY\n": "creds.env:1"}, textOccurrences(fs))
}

// Git reads delta chains of any depth; repack --depth=250 is a common
// recommendation for large repositories.
func TestDeepDeltaChain(t *testing.T) {
	repo := initRepo(t)
	lines := make([]string, 400)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %03d %s\n", i, strings.Repeat("x", 40))
	}
	var stream bytes.Buffer
	for i := range 300 {
		lines[(i*7)%len(lines)] = fmt.Sprintf("edit %03d %s\n", i, strings.Repeat("y", 40))
		content := strings.Join(lines, "")
		if i == 0 {
			content += "TOKEN_DEEP_ROOT\n"
		}
		fmt.Fprintf(&stream, "commit refs/heads/main\nmark :%d\ncommitter Coverage <coverage@example.test> %d +0000\ndata 3\nc%d\n", i+1, 1700000000+i, i%10)
		if i > 0 {
			fmt.Fprintf(&stream, "from :%d\n", i)
		}
		fmt.Fprintf(&stream, "M 100644 inline f.txt\ndata %d\n%s\n", len(content), content)
	}
	gitInput(t, repo, stream.Bytes(), "fast-import", "--quiet")
	gitFixture(t, repo, "repack", "-adfq", "--depth=250", "--window=250")
	packs, err := filepath.Glob(filepath.Join(repo, ".git", "objects", "pack", "*.idx"))
	require.NoError(t, err)
	require.Len(t, packs, 1)
	deepest, depth := "", 0
	for _, line := range strings.Split(gitFixture(t, repo, "verify-pack", "-v", packs[0]), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 7 && fields[1] == "blob" {
			if d, err := strconv.Atoi(fields[5]); err == nil && d > depth {
				deepest, depth = fields[0], d
			}
		}
	}
	require.Greater(t, depth, 128, "fixture must exceed the former recursion limit")
	t.Setenv("PATH", t.TempDir())
	r, cleanup, err := (&Source{RepoPath: repo, CacheMiB: 1}).open(t.Context())
	require.NoError(t, err)
	defer cleanup()
	store := r.Storer.(*objectStorage)
	o, err := store.read(gitobj.NewHash(deepest))
	require.NoError(t, err)
	h := gitobj.NewHasher(format.SHA1, o.Type(), o.Size())
	h.Write([]byte(o.raw))
	require.Equal(t, deepest, h.Sum().String())
	found := false
	for _, f := range collect(t, &Source{RepoPath: repo}) {
		found = found || strings.Contains(f.Raw, "TOKEN_DEEP_ROOT")
	}
	require.True(t, found)
}

// A commit beyond the tree comparison budget is skipped with a warning, and
// the rest of history is still scanned.
func TestOversizedCommitIsSkipped(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "early.txt", "TOKEN_EARLY\n", "early")
	blob := gitInput(t, repo, []byte("x\n"), "hash-object", "-w", "--stdin")
	var entries bytes.Buffer
	for i := range maxTreeChanges + 1 {
		fmt.Fprintf(&entries, "100644 blob %s\tf%06d\n", blob, i)
	}
	tree := gitInput(t, repo, entries.Bytes(), "mktree")
	wide := gitFixture(t, repo, "commit-tree", tree, "-p", "HEAD", "-m", "wide")
	gitFixture(t, repo, "update-ref", "refs/heads/main", wide)
	t.Setenv("PATH", t.TempDir())
	var mu sync.Mutex
	var fs []sources.Fragment
	var logs bytes.Buffer
	err := (&Source{RepoPath: repo, Logger: slog.New(slog.NewTextHandler(&logs, nil))}).Fragments(t.Context(), func(f sources.Fragment, err error) error {
		mu.Lock()
		defer mu.Unlock()
		require.NoError(t, err)
		fs = append(fs, f)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(logs.String(), "skipped Git content over a limit"))
	require.Contains(t, logs.String(), wide)
	require.Equal(t, map[string]string{"TOKEN_EARLY\n": "early.txt:1"}, textOccurrences(fs))
}

// Rename scoring reads whole blobs. A rename candidate over the read limit
// must not cost its commit's other files: the first public-repository battery
// missed a secret added beside a replaced 70 MB binary.
func TestOversizedRenameCandidateKeepsCommit(t *testing.T) {
	repo := initRepo(t)
	big := strings.Repeat("\x00", defaultMaxBlobBytes+1)
	commitFile(t, repo, "old.bin", big+"a", "binary")
	gitFixture(t, repo, "rm", "-q", "old.bin")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("TOKEN_BESIDE\n"), 0600))
	gitFixture(t, repo, "add", "secret.txt")
	commitFile(t, repo, "new.bin", big+"b", "replace")
	var mu sync.Mutex
	var fs []sources.Fragment
	var logs bytes.Buffer
	err := (&Source{RepoPath: repo, Logger: slog.New(slog.NewTextHandler(&logs, nil))}).Fragments(t.Context(), func(f sources.Fragment, err error) error {
		mu.Lock()
		defer mu.Unlock()
		require.NoError(t, err)
		fs = append(fs, f)
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"TOKEN_BESIDE\n": "secret.txt:1"}, textOccurrences(fs))
	require.Contains(t, logs.String(), `path \"new.bin\"`)
}

func TestRevisionRange(t *testing.T) {
	repo := newHistory(t)
	t.Setenv("PATH", t.TempDir())
	// Commits on main that side lacks: modify, rename, merge, and attributes.
	// Only the merge's first-parent patch adds side.txt, as git log -p
	// --diff-merges=first-parent reports it.
	onMain := map[string]string{"TOKEN_CHANGED\n": "file.txt:2"}
	require.Equal(t, onMain, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: "side..main"})))
	require.Equal(t, map[string]string{"TOKEN_CHANGED\n": "file.txt:2", "TOKEN_SIDE\n": "side.txt:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: "side..main", Include: []string{"merges"}})))
	// An omitted end means HEAD, like Git.
	require.Equal(t, onMain, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: "side.."})))
	require.Empty(t, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: "main..side"})))
	require.ErrorContains(t, (&Source{RepoPath: repo, Revision: "missing..main"}).Fragments(t.Context(), func(sources.Fragment, error) error { return nil }), "missing")
}

func TestCommitList(t *testing.T) {
	repo := newHistory(t)
	gitFixture(t, repo, "tag", "-a", "-m", "modify", "modify", "main~3")
	id := func(rev string) string { return gitFixture(t, repo, "rev-parse", rev) }
	root := id("main~4")
	modify := id("main~3")
	merge := id("main~1")
	side := id("side")
	tag := id("modify")
	tree, blob, missing := id("main^{tree}"), id("main:renamed.txt"), strings.Repeat("a", 40)
	t.Setenv("PATH", t.TempDir())
	changed := map[string]string{"TOKEN_CHANGED\n": "file.txt:2"}
	for _, tc := range []struct {
		name   string
		source Source
		want   map[string]string
	}{
		{"no ancestors", Source{Commits: []string{modify}}, changed},
		{"annotated tag", Source{Commits: []string{tag}}, changed},
		{"duplicates", Source{Commits: []string{modify, modify, tag}}, changed},
		{"separate branches", Source{Commits: []string{side, modify}}, map[string]string{
			"TOKEN_SIDE\n": "side.txt:1", "TOKEN_CHANGED\n": "file.txt:2",
		}},
		{"root commit", Source{Commits: []string{root}}, map[string]string{
			"first\nTOKEN_ROOT\nlast\n": "file.txt:1",
		}},
		{"empty list", Source{Commits: []string{}}, map[string]string{}},
		{"merge excluded", Source{Commits: []string{merge}}, map[string]string{}},
		{"merge included", Source{Commits: []string{merge}, Include: []string{"merges"}}, map[string]string{
			"TOKEN_SIDE\n": "side.txt:1",
		}},
		{"filtered list", Source{Commits: []string{side, modify}, Author: "modify <", MaxCount: 1}, changed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.source.RepoPath = repo
			fragments := collect(t, &tc.source)
			require.Equal(t, tc.want, textOccurrences(fragments))
			require.Len(t, fragments, len(tc.want))
		})
	}
	t.Run("commit messages", func(t *testing.T) {
		fragments := collect(t, &Source{
			RepoPath: repo, Commits: []string{modify, side},
			Include: []string{"commit-messages"}, Exclude: []string{"history"},
		})
		var commits []string
		for _, fragment := range fragments {
			require.Equal(t, sources.ResourceGitCommitMessage, fragment.Attr(sources.AttrResource))
			commits = append(commits, fragment.Attr(sources.AttrGitSHA))
		}
		require.ElementsMatch(t, []string{modify, side}, commits)
	})
	for name, bad := range map[string]string{"tree": tree, "blob": blob, "missing": missing} {
		t.Run(name, func(t *testing.T) {
			source := &Source{RepoPath: repo, Commits: []string{modify, bad}}
			err := source.Fragments(t.Context(), func(sources.Fragment, error) error {
				t.Error("invalid commit list must fail before yielding fragments")
				return nil
			})
			require.ErrorContains(t, err, bad)
		})
	}
}

func TestExternalStores(t *testing.T) {
	other := newHistory(t)
	noYield := func(sources.Fragment, error) error { return errors.New("yield from external storage") }
	pointer := func(dir, target string) string {
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: "+target+"\n"), 0600))
		return dir
	}

	// Each case clears PATH only after its fixture is built with git.
	t.Run("gitdir file", func(t *testing.T) {
		dir := pointer(t.TempDir(), filepath.Join(other, ".git"))
		t.Setenv("PATH", t.TempDir())
		require.ErrorIs(t, (&Source{RepoPath: dir}).Fragments(t.Context(), noYield), ErrExternalStore)
		require.NotEmpty(t, textOccurrences(collect(t, &Source{RepoPath: dir, AllowExternalObjects: true})))
	})
	t.Run("forged worktree", func(t *testing.T) {
		linked := filepath.Join(t.TempDir(), "linked")
		gitFixture(t, other, "worktree", "add", "-q", "--detach", linked)
		t.Setenv("PATH", t.TempDir())
		require.NotEmpty(t, textOccurrences(collect(t, &Source{RepoPath: linked})), "a registered worktree is not external")
		// Another directory naming the same worktree Git directory is not the
		// worktree its main repository registered.
		forged := pointer(t.TempDir(), filepath.Join(other, ".git", "worktrees", "linked"))
		require.ErrorIs(t, (&Source{RepoPath: forged}).Fragments(t.Context(), noYield), ErrExternalStore)
	})
	t.Run("commondir", func(t *testing.T) {
		repo := initRepo(t)
		commitFile(t, repo, "file", "TOKEN_LOCAL\n", "local")
		t.Setenv("PATH", t.TempDir())
		require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "commondir"), []byte(filepath.Join(other, ".git")+"\n"), 0600))
		require.ErrorIs(t, (&Source{RepoPath: repo}).Fragments(t.Context(), noYield), ErrExternalStore)
	})
	t.Run("alternate", func(t *testing.T) {
		repo := initRepo(t)
		commitFile(t, repo, "file", "TOKEN_LOCAL\n", "local")
		t.Setenv("PATH", t.TempDir())
		alternates := filepath.Join(repo, ".git", "objects", "info", "alternates")
		require.NoError(t, os.WriteFile(alternates, []byte(filepath.Join(other, ".git", "objects")+"\n"), 0600))
		require.ErrorIs(t, (&Source{RepoPath: repo, Include: []string{"objects"}, Exclude: []string{"history"}}).Fragments(t.Context(), noYield), ErrExternalStore)
		require.NoError(t, os.WriteFile(alternates, []byte("# comment\n\n"), 0600))
		require.Equal(t, map[string]string{"TOKEN_LOCAL\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo})))
	})
}

// The object reader must find exactly the added lines git log -p reports, with and
// without merge patches, for history with modifications, deletions, renames,
// merges, mode changes, and an unterminated final line. Every line in the fixture
// is unique, so the diff is unambiguous and the two implementations must agree.
func TestMatchesGitLog(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "a.txt", "a1\na2\na3\na4\na5\na6\na7\na8\n", "add a")
	commitFile(t, repo, "b.txt", "b1\nb2\n", "add b")
	root := gitFixture(t, repo, "rev-parse", "HEAD")
	commitFile(t, repo, "a.txt", "a1\na2\nA3\na4\na5\na6\na7\na8\na9\n", "modify a")
	gitFixture(t, repo, "rm", "-q", "b.txt")
	commitFile(t, repo, "c.txt", "c1\nc2", "delete b, add unterminated c")
	commitFile(t, repo, "c.txt", "c1\nc2c3", "extend unterminated line")
	require.NoError(t, os.Mkdir(filepath.Join(repo, "dir"), 0700))
	gitFixture(t, repo, "mv", "a.txt", "dir/d.txt")
	commitFile(t, repo, "dir/d.txt", "a1\na2\nA3\na4\na5\na6\na7\na8\na9\nd10\n", "rename a with an edit")
	// update-index sets the mode where the file system has no executable bit.
	require.NoError(t, os.Chmod(filepath.Join(repo, "c.txt"), 0700))
	gitFixture(t, repo, "update-index", "--chmod=+x", "c.txt")
	gitFixture(t, repo, "commit", "-qm", "mode only")
	gitFixture(t, repo, "checkout", "-qb", "side", root)
	commitFile(t, repo, "s.txt", "s1\ns2\n", "side")
	gitFixture(t, repo, "checkout", "-q", "main")
	gitFixture(t, repo, "merge", "-q", "--no-ff", "side", "-m", "merge side")
	commitFile(t, repo, "e.txt", "e1\n", "after merge")

	type line struct {
		sha, path, text string
		number          int
	}
	lines := func(fs []sources.Fragment) map[line]int {
		result := map[line]int{}
		for _, f := range fs {
			for i, text := range strings.SplitAfter(f.Raw, "\n") {
				if text != "" {
					result[line{f.Attr(sources.AttrGitSHA), f.Attr(sources.AttrPath), text, f.StartLine + i}]++
				}
			}
		}
		return result
	}
	fromGit := func(merges string) map[line]int {
		patch := gitFixture(t, repo, "log", "-p", "--all", "--diff-merges="+merges, "--no-ext-diff", "--no-textconv",
			"--no-color", "--format=medium", "--no-abbrev-commit", "--src-prefix=a/", "--dst-prefix=b/", "-U0")
		var mu sync.Mutex
		var fragments []sources.Fragment
		require.NoError(t, (&sources.GitDiff{Content: strings.NewReader(patch + "\n")}).Fragments(t.Context(), func(f sources.Fragment, err error) error {
			require.NoError(t, err)
			mu.Lock()
			defer mu.Unlock()
			fragments = append(fragments, f)
			return nil
		}))
		return lines(fragments)
	}
	withoutMerges, withMerges := fromGit("off"), fromGit("first-parent")
	require.NotEqual(t, withoutMerges, withMerges, "the fixture's merge must add lines")
	t.Setenv("PATH", t.TempDir())
	require.Equal(t, withoutMerges, lines(collect(t, &Source{RepoPath: repo})))
	require.Equal(t, withMerges, lines(collect(t, &Source{RepoPath: repo, Include: []string{"merges"}})))
}

func TestUnsafeStorageFiles(t *testing.T) {
	for _, name := range []string{"loose", "fanout", "pack", "idx", "rev", "pack-directory", "shallow", "alternates", "info-directory", "commondir"} {
		t.Run(name, func(t *testing.T) {
			repo := initRepo(t)
			commitFile(t, repo, "secret", "TOKEN_LOCAL\n", "root")
			gitDir := filepath.Join(repo, ".git")
			var target string
			switch name {
			case "loose", "fanout":
				id := gitFixture(t, repo, "rev-parse", "HEAD:secret")
				target = filepath.Join(gitDir, "objects", id[:2], id[2:])
				if name == "fanout" {
					target = filepath.Dir(target)
				}
			case "pack", "idx", "rev", "pack-directory":
				gitFixture(t, repo, "-c", "pack.writeReverseIndex=true", "repack", "-ad")
				target = filepath.Join(gitDir, "objects", "pack")
				if name != "pack-directory" {
					paths, err := filepath.Glob(filepath.Join(target, "*."+name))
					require.NoError(t, err)
					require.Len(t, paths, 1)
					target = paths[0]
				}
			case "info-directory":
				target = filepath.Join(gitDir, "objects", "info")
			default:
				target = filepath.Join(gitDir, name)
				if name == "alternates" {
					target = filepath.Join(gitDir, "objects", "info", name)
				}
				require.NoError(t, os.WriteFile(target, nil, 0600))
			}
			outside := filepath.Join(t.TempDir(), "outside")
			require.NoError(t, os.Rename(target, outside))
			if err := os.Symlink(outside, target); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			t.Setenv("PATH", t.TempDir())
			for _, allow := range []bool{false, true} {
				// AllowExternalObjects permits explicit stores, not linked files.
				s := &Source{RepoPath: repo, AllowExternalObjects: allow}
				err := s.Fragments(t.Context(), func(f sources.Fragment, err error) error {
					require.Empty(t, f.Raw, "must not expose linked content")
					return err
				})
				require.Error(t, err)
			}
		})
	}
	t.Run("pointer symlink", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "pointer")
		require.NoError(t, os.WriteFile(outside, []byte("gitdir: /other/repo\n"), 0600))
		pointer := filepath.Join(t.TempDir(), ".git")
		if err := os.Symlink(outside, pointer); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		_, err := readGitFile(pointer)
		require.Error(t, err)
	})
	t.Run("FIFOs", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Unix FIFO fixture")
		}
		mkfifo, err := exec.LookPath("mkfifo")
		if err != nil {
			t.Skip("mkfifo fixture generator unavailable")
		}
		root := t.TempDir()
		fs := readOnlyFS{Filesystem: gitfs.New(root), objectRoot: root}
		for _, path := range []string{"shallow", "commondir", "objects/info/alternates", "objects/ab/cd", "objects/pack/pack-test.pack"} {
			full := filepath.Join(root, path)
			require.NoError(t, os.MkdirAll(filepath.Dir(full), 0700))
			out, err := exec.Command(mkfifo, full).CombinedOutput()
			require.NoError(t, err, "%s", out)
			_, err = fs.Open(path)
			require.ErrorContains(t, err, "not a regular file")
		}
		_, err = readSmallFile(filepath.Join(root, "commondir"))
		require.ErrorContains(t, err, "not a regular file")
		_, err = (layout{common: root}).alternates()
		require.ErrorContains(t, err, "not a regular file")
		_, err = readShallow(fs)
		require.ErrorContains(t, err, "not a regular file")
		out, err := exec.Command(mkfifo, filepath.Join(root, "refs")).CombinedOutput()
		require.NoError(t, err, "%s", out)
		_, err = fs.ReadDir("refs")
		require.ErrorContains(t, err, "not a directory")
	})
}

func TestShallowLimits(t *testing.T) {
	root := t.TempDir()
	fs := readOnlyFS{Filesystem: gitfs.New(root), objectRoot: root}
	path := filepath.Join(root, "shallow")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("1", 40)+"\n"), 0600))
	ids, err := readShallow(fs)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.NoError(t, os.Truncate(path, maxShallowBytes+1))
	_, err = readShallow(fs)
	require.ErrorContains(t, err, "exceeds")
}
