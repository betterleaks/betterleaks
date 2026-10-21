package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
)

// gitFixture is a test repository driven by the Git CLI, without the user's
// global or system configuration.
type gitFixture struct {
	t    *testing.T
	path string
}

func newGitFixture(t *testing.T, initArgs ...string) *gitFixture {
	t.Helper()
	f := &gitFixture{t: t, path: t.TempDir()}
	f.git(append(append([]string{"init", "-q", "-b", "main"}, initArgs...), ".")...)
	f.git("config", "user.name", "Test User")
	f.git("config", "user.email", "test@example.com")
	f.git("config", "commit.gpgSign", "false")
	return f
}

func (f *gitFixture) gitIn(dir, stdin string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = gitConfigIsolationEnv()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	require.NoError(f.t, err, "git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

func (f *gitFixture) git(args ...string) string {
	f.t.Helper()
	return f.gitIn(f.path, "", args...)
}

func (f *gitFixture) write(name, content string) {
	f.t.Helper()
	path := filepath.Join(f.path, name)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(f.t, os.WriteFile(path, []byte(content), 0o644))
}

func (f *gitFixture) appendConfig(text string) {
	f.t.Helper()
	file, err := os.OpenFile(filepath.Join(f.path, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(f.t, err)
	_, err = file.WriteString(text)
	require.NoError(f.t, errors.Join(err, file.Close()))
}

func (f *gitFixture) commit(message string) string {
	f.t.Helper()
	f.git("add", "-A")
	f.git("commit", "-q", "-m", message)
	return f.git("rev-parse", "HEAD")
}

// signedCommit commits the index with a gpgsig header, which
// log.showSignature asks Git to verify with gpg.program.
func (f *gitFixture) signedCommit(message string) {
	f.t.Helper()
	f.git("add", "-A")
	body := fmt.Sprintf("tree %s\nparent %s\n"+
		"author Test User <test@example.com> 1700000000 +0000\n"+
		"committer Test User <test@example.com> 1700000000 +0000\n"+
		"gpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n\n%s\n",
		f.git("write-tree"), f.git("rev-parse", "HEAD"), message)
	f.git("update-ref", "HEAD", f.gitIn(f.path, body, "hash-object", "-t", "commit", "-w", "--stdin"))
}

// scanGit returns the fragments a scan yields, as sorted "sha path:line raw" strings.
func scanGit(t *testing.T, path, mode, logOpts string, opts GitOptions) []string {
	t.Helper()
	ctx := t.Context()
	sema := semgroup.NewGroup(ctx, 4)
	var src Source
	switch mode {
	case "history":
		cmd, err := opts.NewLogCmd(ctx, path, logOpts)
		require.NoError(t, err)
		src = &Git{Cmd: cmd, Sema: sema, MaxArchiveDepth: 2}
	case "parallel":
		src = &ParallelGit{RepoPath: path, LogOpts: logOpts, Workers: 2, Sema: sema, MaxArchiveDepth: 2, TrustLocalGitConfig: opts.TrustLocalGitConfig}
	case "staged", "worktree":
		cmd, err := opts.NewDiffCmd(ctx, path, mode == "staged")
		require.NoError(t, err)
		src = &Git{Cmd: cmd, Sema: sema, MaxArchiveDepth: 2}
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	var (
		mu        sync.Mutex
		fragments []string
		errs      []error
	)
	require.NoError(t, src.Fragments(ctx, func(f Fragment, err error) error {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		fragments = append(fragments, fmt.Sprintf("%s %s:%d %s", f.Attr(AttrGitSHA), f.Attr(AttrPath), f.StartLine, f.Raw))
		return nil
	}))
	require.NoError(t, sema.Wait())
	require.NoError(t, errors.Join(errs...))
	slices.Sort(fragments)
	return fragments
}

// useTempDir points os.TempDir at a fresh directory and returns it.
func useTempDir(t *testing.T) string {
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
	return dir
}

var gitScanModes = []string{"history", "parallel", "staged", "worktree"}

func TestGitIsolationBlocksRepositoryPrograms(t *testing.T) {
	f := newGitFixture(t)
	f.write(".gitattributes", "*.txt diff=hostile filter=hostile\n")
	f.write("secret.txt", "HISTORY_SECRET_ONE\n")
	f.commit("first")
	f.write("secret.txt", "HISTORY_SECRET_TWO\n")
	f.commit("second")
	f.write("signed.txt", "SIGNED_COMMIT_SECRET\n")
	f.signedCommit("signed")
	f.write("secret.txt", "STAGED_SECRET\n")
	f.git("add", "secret.txt")
	f.write("secret.txt", "WORKTREE_SECRET\n")

	want := make(map[string][]string)
	for _, mode := range gitScanModes {
		want[mode] = scanGit(t, f.path, mode, "", GitOptions{TrustLocalGitConfig: true})
		require.NotEmpty(t, want[mode], mode)
	}

	// Every helper appends to the marker and passes its input through.
	dir := t.TempDir()
	marker := filepath.ToSlash(filepath.Join(dir, "marker"))
	helper := filepath.ToSlash(filepath.Join(dir, "helper"))
	script := fmt.Sprintf("#!/bin/sh\necho \"$0 $*\" >> '%s'\ncat\n", marker)
	require.NoError(t, os.WriteFile(helper, []byte(script), 0o755))
	shell := "'" + helper + "'"
	included := filepath.Join(dir, "included.config")
	require.NoError(t, os.WriteFile(included, []byte(fmt.Sprintf("[diff \"hostile\"]\n\ttextconv = %q\n", shell)), 0o600))
	hooks := filepath.Join(dir, "hooks")
	for _, hooksDir := range []string{hooks, filepath.Join(f.path, ".git", "hooks")} {
		for _, hook := range []string{"post-index-change", "reference-transaction"} {
			require.NoError(t, os.MkdirAll(hooksDir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(hooksDir, hook), []byte(script), 0o755))
		}
	}
	f.git("config", "include.path", filepath.ToSlash(included))
	for key, value := range map[string]string{
		"diff.hostile.command":  shell,
		"filter.hostile.clean":  shell,
		"filter.hostile.smudge": shell,
		"diff.external":         shell,
		"core.fsmonitor":        shell,
		"core.pager":            shell,
		"core.hooksPath":        filepath.ToSlash(hooks),
		"log.showSignature":     "true",
		"gpg.program":           helper,
	} {
		f.git("config", key, value)
	}
	f.write(".git/info/attributes", "* diff=hostile filter=hostile\n")
	// Make the index stale, so a working-tree diff would refresh and rewrite it.
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(filepath.Join(f.path, ".gitattributes"), future, future))

	original := make(map[string][]byte)
	for _, name := range []string{"config", "index", "HEAD"} {
		data, err := os.ReadFile(filepath.Join(f.path, ".git", name))
		require.NoError(t, err)
		original[name] = data
	}
	for _, mode := range gitScanModes {
		t.Run(mode, func(t *testing.T) {
			require.Equal(t, want[mode], scanGit(t, f.path, mode, "", GitOptions{}))
			require.NoFileExists(t, marker)
		})
	}
	for name, data := range original {
		current, err := os.ReadFile(filepath.Join(f.path, ".git", name))
		require.NoError(t, err)
		require.Equal(t, data, current, name)
	}

	// Positive control: trusting the repository runs its textconv and gpg.program.
	cmd, err := GitOptions{TrustLocalGitConfig: true}.NewLogCmd(t.Context(), f.path, "")
	require.NoError(t, err)
	for range cmd.DiffFilesCh() {
	}
	for range cmd.ErrCh() {
	}
	_ = cmd.Wait()
	ran, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Contains(t, string(ran), "--verify", "gpg.program should run")
	require.Contains(t, string(ran), "secret.txt", "textconv should run")
}

func TestGitIsolationSkipsSubmodules(t *testing.T) {
	sub := newGitFixture(t)
	sub.write("file.txt", "SUBMODULE\n")
	sub.commit("sub")
	f := newGitFixture(t)
	f.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", sub.path, "sub")
	f.commit("add submodule")
	f.write("secret.txt", "WORKTREE_SECRET\n")
	f.git("add", "secret.txt")
	f.write("secret.txt", "WORKTREE_SECRET_TWO\n")
	f.write("sub/file.txt", "DIRTY\n")

	// Checking the dirty submodule would run Git with the submodule's configuration.
	marker := filepath.ToSlash(filepath.Join(t.TempDir(), "marker"))
	f.gitIn(filepath.Join(f.path, "sub"), "", "config", "core.fsmonitor", fmt.Sprintf("echo ran >> '%s'; false", marker))
	for _, mode := range []string{"staged", "worktree"} {
		require.NotEmpty(t, scanGit(t, f.path, mode, "", GitOptions{}), mode)
		require.NoFileExists(t, marker, mode)
	}
}

func TestGitIsolationMatchesTrustedScans(t *testing.T) {
	populate := func(f *gitFixture) {
		f.write("secret.txt", "HISTORY_SECRET\n")
		f.write("sub/nested.txt", "NESTED_SECRET\n")
		f.commit("first")
		f.git("branch", "side")
		f.git("tag", "-a", "-m", "tag", "v1")
		f.write("secret.txt", "SECOND_SECRET\n")
		f.write("archive.zip", string(buildGitHubTestZip(t, map[string]string{"inner.txt": "ARCHIVE_SECRET\n"})))
		f.commit("second")
		f.git("pack-refs", "--all")
		f.write("secret.txt", "STAGED_SECRET\n")
		f.write("sub/nested.txt", "NESTED_STAGED_SECRET\n")
		f.git("add", "-A")
		f.write("secret.txt", "WORKTREE_SECRET\n")
		f.write("sub/nested.txt", "NESTED_WORKTREE_SECRET\n")
	}
	type layout struct {
		name     string
		initArgs []string
		path     func(f *gitFixture) string
		modes    []string
	}
	layouts := []layout{
		{name: "default", modes: gitScanModes},
		{name: "sha256", initArgs: []string{"--object-format=sha256"}, modes: gitScanModes},
		{name: "reftable", initArgs: []string{"--ref-format=reftable"}, modes: gitScanModes},
		{name: "subdirectory", path: func(f *gitFixture) string { return filepath.Join(f.path, "sub") }, modes: gitScanModes},
		{name: "bare", path: func(f *gitFixture) string {
			bare := filepath.Join(t.TempDir(), "bare.git")
			f.git("clone", "-q", "--bare", f.path, bare)
			return bare
		}, modes: []string{"history", "parallel"}},
		{name: "shallow", path: func(f *gitFixture) string {
			shallow := filepath.Join(t.TempDir(), "shallow.git")
			f.git("clone", "-q", "--bare", "--depth=1", "--no-single-branch", "--no-local", f.path, shallow)
			return shallow
		}, modes: []string{"history", "parallel"}},
		{name: "linked worktree", path: func(f *gitFixture) string {
			wt := filepath.Join(t.TempDir(), "wt")
			f.git("worktree", "add", "-q", "-b", "wt", wt)
			f.gitIn(wt, "", "commit", "-q", "--allow-empty", "-m", "worktree")
			require.NoError(t, os.WriteFile(filepath.Join(wt, "wt.txt"), []byte("WT_STAGED_SECRET\n"), 0o644))
			f.gitIn(wt, "", "add", "wt.txt")
			require.NoError(t, os.WriteFile(filepath.Join(wt, "wt.txt"), []byte("WT_WORKTREE_SECRET\n"), 0o644))
			return wt
		}, modes: gitScanModes},
	}
	for _, l := range layouts {
		t.Run(l.name, func(t *testing.T) {
			cmd := exec.Command("git", append(append([]string{"init", "-q"}, l.initArgs...), t.TempDir())...)
			cmd.Env = gitConfigIsolationEnv()
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("git does not support %v: %s", l.initArgs, out)
			}
			f := newGitFixture(t, l.initArgs...)
			populate(f)
			path := f.path
			if l.path != nil {
				path = l.path(f)
			}
			for _, mode := range l.modes {
				for _, logOpts := range []string{"", "--all", "side..main"} {
					if logOpts != "" && (mode == "staged" || mode == "worktree") {
						continue
					}
					trusted := scanGit(t, path, mode, logOpts, GitOptions{TrustLocalGitConfig: true})
					require.NotEmpty(t, trusted, "%s %s", mode, logOpts)
					require.Equal(t, trusted, scanGit(t, path, mode, logOpts, GitOptions{}), "%s %s", mode, logOpts)
				}
			}
		})
	}
}

func TestGitIsolationHistoryPathspecs(t *testing.T) {
	f := newGitFixture(t)
	for i := range 3 {
		for _, name := range []string{"nested.txt", "sub/nested.txt", "sub/skip.txt", "sub/with space.txt", "sub/deep/inner.txt"} {
			f.write(name, fmt.Sprintf("SECRET_%d_%s\n", i, name))
		}
		f.commit(fmt.Sprintf("commit %d", i))
	}
	path := filepath.Join(f.path, "sub")
	for _, opts := range []string{
		"--all -- nested.txt",
		"--all -- .",
		"--all -- ../nested.txt",
		"--all -- 'with space.txt'",
		"--all -- '*.txt' ':(exclude)skip.txt'",
		"--all -- ':(glob)**/*.txt' ':(exclude)deep/*'",
		"--all -- ':(top)nested.txt'",
		"--all -- ':/nested.txt'",
		"--all -- ':(literal)nested.txt'",
		"--all -- '" + filepath.ToSlash(filepath.Join(path, "nested.txt")) + "'",
	} {
		t.Run(opts, func(t *testing.T) {
			want := scanGit(t, path, "history", opts, GitOptions{TrustLocalGitConfig: true})
			require.NotEmpty(t, want)
			for _, mode := range []string{"history", "parallel"} {
				require.Equal(t, want, scanGit(t, path, mode, opts, GitOptions{}), mode)
			}
		})
	}
	// The caller's working-tree attributes must still not hide history.
	f.write(".gitattributes", "*.txt -diff\n")
	got := scanGit(t, path, "history", "--all -- nested.txt", GitOptions{})
	require.Len(t, got, 3)
}

func TestGitIsolationSymlinkedSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require privileges on Windows")
	}
	f := newGitFixture(t)
	for i := range 3 {
		f.write("sub/secret.txt", fmt.Sprintf("HISTORY_SECRET_%d\n", i))
		f.write("other.txt", fmt.Sprintf("OTHER_SECRET_%d\n", i))
		f.commit(fmt.Sprintf("commit %d", i))
	}
	f.write("sub/deleted.txt", "DELETED_HISTORY_SECRET\n")
	f.commit("historical file")
	f.git("rm", "sub/deleted.txt")
	f.commit("delete historical file")
	f.write("sub/secret.txt", "STAGED_SECRET\n")
	f.git("add", "sub/secret.txt")
	f.write("sub/secret.txt", "WORKTREE_SECRET\n")
	link := filepath.Join(t.TempDir(), "linked-subdirectory")
	require.NoError(t, os.Symlink(filepath.Join(f.path, "sub"), link))
	for _, mode := range gitScanModes {
		t.Run(mode, func(t *testing.T) {
			logOpts := ""
			if mode == "history" || mode == "parallel" {
				logOpts = "--all -- secret.txt"
			}
			want := scanGit(t, link, mode, logOpts, GitOptions{TrustLocalGitConfig: true})
			require.NotEmpty(t, want)
			require.Equal(t, want, scanGit(t, link, mode, logOpts, GitOptions{}))
		})
	}
	rootLink := filepath.Join(t.TempDir(), "linked-root")
	require.NoError(t, os.Symlink(f.path, rootLink))
	for _, pathspec := range []string{"secret.txt", "deleted.txt", "*.txt"} {
		t.Run("absolute/"+pathspec, func(t *testing.T) {
			opts := "--all -- '" + filepath.ToSlash(filepath.Join(rootLink, "sub", pathspec)) + "'"
			want := scanGit(t, link, "history", opts, GitOptions{TrustLocalGitConfig: true})
			require.NotEmpty(t, want)
			for _, mode := range []string{"history", "parallel"} {
				require.Equal(t, want, scanGit(t, link, mode, opts, GitOptions{}))
			}
		})
	}
}

func TestGitIsolationConfiguredWorktree(t *testing.T) {
	for _, relative := range []bool{false, true} {
		for _, worktreeConfig := range []bool{false, true} {
			t.Run(fmt.Sprintf("relative=%t/worktreeConfig=%t", relative, worktreeConfig), func(t *testing.T) {
				f := newGitFixture(t)
				for i := range 3 {
					f.write("secret.txt", fmt.Sprintf("HISTORY_SECRET_%d\n", i))
					f.write("sub/nested.txt", fmt.Sprintf("NESTED_SECRET_%d\n", i))
					f.commit(fmt.Sprintf("commit %d", i))
				}
				worktree := filepath.Join(f.path, "tree")
				require.NoError(t, os.Mkdir(worktree, 0o755))
				for _, name := range []string{"secret.txt", "sub"} {
					require.NoError(t, os.Rename(filepath.Join(f.path, name), filepath.Join(worktree, name)))
				}
				value := filepath.ToSlash(worktree)
				if relative {
					value = "../tree"
				}
				if worktreeConfig {
					f.git("config", "extensions.worktreeConfig", "true")
					// The per-worktree value must override this common setting.
					f.git("config", "core.worktree", "..")
					f.git("config", "--worktree", "core.worktree", value)
				} else {
					f.git("config", "core.worktree", value)
				}
				for _, name := range []string{"secret.txt", "sub/nested.txt"} {
					require.NoError(t, os.WriteFile(filepath.Join(worktree, name), []byte("STAGED_SECRET\n"), 0o644))
				}
				f.gitIn(worktree, "", "add", "-A")
				for _, name := range []string{"secret.txt", "sub/nested.txt"} {
					require.NoError(t, os.WriteFile(filepath.Join(worktree, name), []byte("WORKTREE_SECRET\n"), 0o644))
				}
				for _, sub := range []string{"", "sub"} {
					for _, mode := range gitScanModes {
						t.Run(filepath.Join(sub, mode), func(t *testing.T) {
							path := filepath.Join(worktree, sub)
							logOpts := ""
							if mode == "history" || mode == "parallel" {
								logOpts = "--all -- ."
							}
							want := scanGit(t, path, mode, logOpts, GitOptions{TrustLocalGitConfig: true})
							require.NotEmpty(t, want)
							require.Equal(t, want, scanGit(t, path, mode, logOpts, GitOptions{}))
						})
					}
				}
			})
		}
	}
}

func TestGitIsolationWorktreeRootPrecedence(t *testing.T) {
	for _, kind := range []string{"linked", "linked-config.worktree", "GIT_WORK_TREE"} {
		t.Run(kind, func(t *testing.T) {
			f := newGitFixture(t)
			for i := range 3 {
				f.write("secret.txt", fmt.Sprintf("HISTORY_SECRET_%d\n", i))
				f.commit(fmt.Sprintf("commit %d", i))
			}
			path := f.path
			if strings.HasPrefix(kind, "linked") {
				path = filepath.Join(t.TempDir(), "linked")
				f.git("worktree", "add", "-q", "-b", "linked", path)
				f.git("config", "core.worktree", filepath.ToSlash(f.path))
				if kind == "linked-config.worktree" {
					f.git("config", "extensions.worktreeConfig", "true")
					layout, err := findGitLayout(path)
					require.NoError(t, err)
					// A relative override is relative to this worktree's Git
					// directory, not the common directory or source argument.
					rel, err := filepath.Rel(layout.gitDir, path)
					require.NoError(t, err)
					f.gitIn(path, "", "config", "--worktree", "core.worktree", filepath.ToSlash(rel))
				}
			} else {
				f.git("config", "core.worktree", "../missing")
				t.Setenv("GIT_WORK_TREE", path)
			}
			require.NoError(t, os.WriteFile(filepath.Join(path, "secret.txt"), []byte("STAGED_SECRET\n"), 0o644))
			f.gitIn(path, "", "add", "secret.txt")
			require.NoError(t, os.WriteFile(filepath.Join(path, "secret.txt"), []byte("WORKTREE_SECRET\n"), 0o644))
			for _, mode := range gitScanModes {
				want := scanGit(t, path, mode, "", GitOptions{TrustLocalGitConfig: true})
				require.NotEmpty(t, want)
				require.Equal(t, want, scanGit(t, path, mode, "", GitOptions{}), mode)
			}
		})
	}
}

func TestGitIsolationMailmap(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprintf("linked=%t", linked), func(t *testing.T) {
			f := newGitFixture(t)
			f.write(".mailmap", "Canonical User <canonical@example.com> <test@example.com>\n")
			for i := range 3 {
				f.write("sub/secret.txt", fmt.Sprintf("SECRET_%d\n", i))
				f.commit(fmt.Sprintf("commit %d", i))
			}
			path := f.path
			if linked {
				path = filepath.Join(t.TempDir(), "worktree")
				f.git("worktree", "add", "-q", "-b", "worktree", path)
			}
			mailmap := filepath.Join(path, ".mailmap")
			check := func(t *testing.T, want string, trustModes ...bool) {
				t.Helper()
				if len(trustModes) == 0 {
					trustModes = []bool{true, false}
				}
				for _, mode := range []string{"history", "parallel"} {
					for _, trusted := range trustModes {
						sema := semgroup.NewGroup(t.Context(), 4)
						var src Source
						if mode == "history" {
							cmd, err := (GitOptions{TrustLocalGitConfig: trusted}).NewLogCmd(t.Context(), filepath.Join(path, "sub"), "--all -- secret.txt")
							require.NoError(t, err)
							src = &Git{Cmd: cmd, Sema: sema}
						} else {
							src = &ParallelGit{RepoPath: filepath.Join(path, "sub"), LogOpts: "--all -- secret.txt", Workers: 2, Sema: sema, TrustLocalGitConfig: trusted}
						}
						var mu sync.Mutex
						var authors []string
						err := src.Fragments(t.Context(), func(fragment Fragment, err error) error {
							if err != nil {
								return err
							}
							mu.Lock()
							defer mu.Unlock()
							authors = append(authors, fragment.Attr(AttrGitAuthorName)+" <"+fragment.Attr(AttrGitAuthorEmail)+">")
							return nil
						})
						require.NoError(t, err)
						require.NoError(t, sema.Wait())
						require.Equal(t, []string{want, want, want}, authors, "%s trusted=%t", mode, trusted)
					}
				}
			}
			t.Run("committed", func(t *testing.T) { check(t, "Canonical User <canonical@example.com>") })
			require.NoError(t, os.WriteFile(mailmap, []byte("Working User <working@example.com> <test@example.com>\n"), 0o644))
			t.Run("modified", func(t *testing.T) { check(t, "Working User <working@example.com>") })
			require.NoError(t, os.Remove(mailmap))
			t.Run("missing", func(t *testing.T) { check(t, "Test User <test@example.com>") })
			t.Run("symlink", func(t *testing.T) {
				if runtime.GOOS == "windows" {
					t.Skip("symlink creation can require privileges on Windows")
				}
				target := filepath.Join(t.TempDir(), "external-mailmap")
				require.NoError(t, os.WriteFile(target, []byte("External User <external@example.com> <test@example.com>\n"), 0o644))
				require.NoError(t, os.Symlink(target, mailmap))
				// Native Git reports a stderr error for the symlink; isolation
				// ignores it without reading the target.
				check(t, "Test User <test@example.com>", false)
			})
		})
	}
}

func TestGitIsolationWorktreeConfig(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(fmt.Sprintf("linked=%t", linked), func(t *testing.T) {
			f := newGitFixture(t)
			f.git("config", "core.autocrlf", "false")
			f.write("secret.txt", "UNCHANGED_SECRET\n")
			f.commit("base")
			f.git("config", "extensions.worktreeConfig", "true")
			path := f.path
			if linked {
				path = filepath.Join(t.TempDir(), "worktree")
				f.git("worktree", "add", "-q", "-b", "worktree", path)
			}
			f.gitIn(path, "", "config", "--worktree", "core.autocrlf", "true")
			require.NoError(t, os.WriteFile(filepath.Join(path, "secret.txt"), []byte("UNCHANGED_SECRET\r\n"), 0o644))
			for _, opts := range []GitOptions{{TrustLocalGitConfig: true}, {}} {
				require.Empty(t, scanGit(t, path, "worktree", "", opts))
			}
			require.NoError(t, os.WriteFile(filepath.Join(path, "secret.txt"), []byte("STAGED_SECRET\r\n"), 0o644))
			f.gitIn(path, "", "add", "secret.txt")
			require.NoError(t, os.WriteFile(filepath.Join(path, "secret.txt"), []byte("WORKTREE_SECRET\r\n"), 0o644))
			want := make(map[string][]string)
			for _, mode := range gitScanModes {
				want[mode] = scanGit(t, path, mode, "", GitOptions{TrustLocalGitConfig: true})
			}
			marker := filepath.ToSlash(filepath.Join(t.TempDir(), "marker"))
			f.gitIn(path, "", "config", "--worktree", "core.fsmonitor", "echo hostile > '"+marker+"'")
			layout, err := findGitLayout(path)
			require.NoError(t, err)
			before, err := os.ReadFile(filepath.Join(layout.gitDir, "config.worktree"))
			require.NoError(t, err)
			for _, mode := range gitScanModes {
				require.Equal(t, want[mode], scanGit(t, path, mode, "", GitOptions{}), mode)
			}
			require.NoFileExists(t, marker)
			after, err := os.ReadFile(filepath.Join(layout.gitDir, "config.worktree"))
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestGitIsolationSparseCheckout(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, kind := range []string{"cone", "sparse-index", "non-cone"} {
			t.Run(fmt.Sprintf("%s/linked=%t", kind, linked), func(t *testing.T) {
				f := newGitFixture(t)
				f.write("included/secret.txt", "BASE\n")
				f.write("excluded/file.txt", "EXCLUDED\n")
				f.commit("base")
				path := f.path
				if linked {
					path = filepath.Join(t.TempDir(), "worktree")
					f.git("worktree", "add", "-q", "-b", "worktree", path)
				}
				args := []string{"sparse-checkout", "set", "--cone", "--no-sparse-index", "included"}
				if kind == "sparse-index" {
					args[3] = "--sparse-index"
				} else if kind == "non-cone" {
					args[2], args[4] = "--no-cone", "/included/"
				}
				f.gitIn(path, "", args...)
				file := filepath.Join(path, "included", "secret.txt")
				require.NoError(t, os.WriteFile(file, []byte("STAGED_SECRET\n"), 0o644))
				f.gitIn(path, "", "add", "included/secret.txt")
				require.NoError(t, os.WriteFile(file, []byte("WORKTREE_SECRET\n"), 0o644))
				want := make(map[string][]string)
				for _, mode := range gitScanModes {
					want[mode] = scanGit(t, path, mode, "", GitOptions{TrustLocalGitConfig: true})
					require.NotEmpty(t, want[mode])
				}
				layout, err := findGitLayout(path)
				require.NoError(t, err)
				before := make(map[string][]byte)
				for _, name := range []string{"index", "config.worktree", "info/sparse-checkout"} {
					before[name], err = os.ReadFile(filepath.Join(layout.gitDir, name))
					require.NoError(t, err)
				}
				for _, mode := range gitScanModes {
					require.Equal(t, want[mode], scanGit(t, path, mode, "", GitOptions{}), mode)
				}
				for name, data := range before {
					after, err := os.ReadFile(filepath.Join(layout.gitDir, name))
					require.NoError(t, err)
					require.Equal(t, data, after, name)
				}
			})
		}
	}
}

func TestGitIsolationIncludesOtherWorktreeHeads(t *testing.T) {
	f := newGitFixture(t)
	f.write("secret.txt", "BASE\n")
	f.commit("base")
	wt := filepath.Join(t.TempDir(), "wt")
	f.git("worktree", "add", "-q", "--detach", wt)
	require.NoError(t, os.WriteFile(filepath.Join(wt, "secret.txt"), []byte("DETACHED_WORKTREE_SECRET\n"), 0o644))
	f.gitIn(wt, "", "commit", "-q", "-am", "detached")

	got := strings.Join(scanGit(t, f.path, "history", "--all", GitOptions{}), "\n")
	require.Contains(t, got, "DETACHED_WORKTREE_SECRET")
}

func TestGitIsolationHistoryIgnoresWorkTreeAttributes(t *testing.T) {
	f := newGitFixture(t)
	f.write(".gitattributes", "*.txt -diff\n")
	f.write("secret.txt", "HIDDEN_BY_ATTRIBUTES\n")
	f.commit("first")

	require.NotContains(t, strings.Join(scanGit(t, f.path, "history", "", GitOptions{TrustLocalGitConfig: true}), "\n"), "HIDDEN_BY_ATTRIBUTES")
	require.Contains(t, strings.Join(scanGit(t, f.path, "history", "", GitOptions{}), "\n"), "HIDDEN_BY_ATTRIBUTES")
}

func TestGitIsolationEnvironment(t *testing.T) {
	t.Run("GIT_INDEX_FILE", func(t *testing.T) {
		f := newGitFixture(t)
		f.write("secret.txt", "BASE\n")
		f.commit("base")
		f.write("secret.txt", "ALTERNATE_INDEX_SECRET\n")
		index := filepath.Join(t.TempDir(), "index")
		cmd := exec.Command("git", "-C", f.path, "add", "secret.txt")
		cmd.Env = append(gitConfigIsolationEnv(), "GIT_INDEX_FILE="+index)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		f.write("secret.txt", "BASE\n")

		t.Setenv("GIT_INDEX_FILE", index)
		require.Contains(t, strings.Join(scanGit(t, f.path, "staged", "", GitOptions{}), "\n"), "ALTERNATE_INDEX_SECRET")
	})

	t.Run("quarantine", func(t *testing.T) {
		// Pre-receive hooks see incoming objects only through these variables.
		f := newGitFixture(t)
		f.write("secret.txt", "BASE\n")
		f.commit("base")
		quarantine := t.TempDir()
		env := []string{
			"GIT_OBJECT_DIRECTORY=" + quarantine,
			"GIT_ALTERNATE_OBJECT_DIRECTORIES=" + filepath.Join(f.path, ".git", "objects"),
		}
		f.write("secret.txt", "QUARANTINED_SECRET\n")
		run := func(stdin string, args ...string) string {
			cmd := exec.Command("git", append([]string{"-C", f.path}, args...)...)
			cmd.Env = append(gitConfigIsolationEnv(), env...)
			cmd.Stdin = strings.NewReader(stdin)
			out, err := cmd.Output()
			require.NoError(t, err)
			return strings.TrimSpace(string(out))
		}
		run("", "add", "secret.txt")
		sha := run("incoming\n", "commit-tree", run("", "write-tree"), "-p", "HEAD")

		for _, e := range env {
			key, value, _ := strings.Cut(e, "=")
			t.Setenv(key, value)
		}
		require.Contains(t, strings.Join(scanGit(t, f.path, "history", sha, GitOptions{}), "\n"), "QUARANTINED_SECRET")
	})

	t.Run("GIT_DIR", func(t *testing.T) {
		f := newGitFixture(t)
		f.write("secret.txt", "GIT_DIR_SECRET\n")
		f.commit("base")
		t.Setenv("GIT_DIR", filepath.Join(f.path, ".git"))
		require.Contains(t, strings.Join(scanGit(t, t.TempDir(), "history", "", GitOptions{}), "\n"), "GIT_DIR_SECRET")
	})
}

func TestGitIsolationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(f *gitFixture) string
		staged bool
		errMsg string
	}{
		{name: "not a repository", setup: func(*gitFixture) string { return t.TempDir() }, errMsg: "not a git repository"},
		{name: "staged scan of a bare repository", staged: true, errMsg: "no working tree", setup: func(f *gitFixture) string {
			bare := filepath.Join(t.TempDir(), "bare.git")
			f.git("clone", "-q", "--bare", f.path, bare)
			return bare
		}},
		{name: "partial clone", errMsg: "--trust-local-git-config", setup: func(f *gitFixture) string {
			f.appendConfig("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tpartialclone = origin\n")
			return f.path
		}},
		{name: "unknown extension", errMsg: "unsupported repository extension", setup: func(f *gitFixture) string {
			f.appendConfig("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tfutureformat = true\n")
			return f.path
		}},
		{name: "unknown format version", errMsg: "unsupported repository format version", setup: func(f *gitFixture) string {
			f.appendConfig("[core]\n\trepositoryformatversion = 2\n")
			return f.path
		}},
		{name: "main repository objects missing", errMsg: "missing object directory", setup: func(f *gitFixture) string {
			wt := filepath.Join(t.TempDir(), "wt")
			f.git("worktree", "add", "-q", "-b", "wt", wt)
			require.NoError(t, os.RemoveAll(filepath.Join(f.path, ".git", "objects")))
			return wt
		}},
		{name: "symlinked ref", errMsg: "not a regular file", setup: func(f *gitFixture) string {
			if runtime.GOOS == "windows" {
				t.Skip("symbolic links need privileges on Windows")
			}
			require.NoError(t, os.Symlink(filepath.Join(f.path, ".git", "config"), filepath.Join(f.path, ".git", "refs", "heads", "link")))
			return f.path
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newGitFixture(t)
			f.write("secret.txt", "SECRET\n")
			f.commit("base")
			path := tt.setup(f)
			temp := useTempDir(t)
			var err error
			if tt.staged {
				_, err = GitOptions{}.NewDiffCmd(t.Context(), path, true)
			} else {
				_, err = GitOptions{}.NewLogCmd(t.Context(), path, "")
			}
			require.ErrorContains(t, err, tt.errMsg)
			entries, err := os.ReadDir(temp)
			require.NoError(t, err)
			require.Empty(t, entries, "private Git directory left behind")
		})
	}
}

func TestGitIsolationRemovesPrivateDirectory(t *testing.T) {
	f := newGitFixture(t)
	f.write("archive.zip", string(buildGitHubTestZip(t, map[string]string{"inner.txt": "ARCHIVE_SECRET\n"})))
	f.commit("archive")
	f.write("secret.txt", "STAGED\n")
	f.git("add", "secret.txt")
	temp := useTempDir(t)
	for _, mode := range gitScanModes {
		got := scanGit(t, f.path, mode, "", GitOptions{})
		if mode == "history" || mode == "parallel" {
			require.Contains(t, strings.Join(got, "\n"), "archive.zip!inner.txt")
		}
		entries, err := os.ReadDir(temp)
		require.NoError(t, err)
		require.Empty(t, entries, mode)
	}
}

func TestGitIsolationRemovesPrivateDirectoryOnCancel(t *testing.T) {
	f := newGitFixture(t)
	for i := range 20 {
		f.write("secret.txt", fmt.Sprintf("SECRET_%d\n", i))
		f.write(fmt.Sprintf("archive%d.zip", i), string(buildGitHubTestZip(t, map[string]string{"inner.txt": "ARCHIVE\n"})))
		f.commit(fmt.Sprintf("commit %d", i))
	}
	temp := useTempDir(t)
	for _, parallel := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		sema := semgroup.NewGroup(ctx, 1)
		var src Source = &ParallelGit{RepoPath: f.path, Workers: 2, Sema: sema, MaxArchiveDepth: 2}
		if !parallel {
			cmd, err := GitOptions{}.NewLogCmd(ctx, f.path, "")
			require.NoError(t, err)
			src = &Git{Cmd: cmd, Sema: sema, MaxArchiveDepth: 2}
		}
		_ = src.Fragments(ctx, func(Fragment, error) error {
			cancel()
			return nil
		})
		_ = sema.Wait()
		cancel()
		entries, err := os.ReadDir(temp)
		require.NoError(t, err)
		require.Empty(t, entries, "parallel=%t", parallel)
	}
}

func TestGitRemoteURL(t *testing.T) {
	tests := []struct {
		name   string
		config [][2]string
	}{
		{name: "origin", config: [][2]string{{"remote.origin.url", "git@github.com:org/repo.git"}}},
		{name: "branch remote", config: [][2]string{
			{"remote.origin.url", "https://example.com/origin.git"},
			{"remote.upstream.url", "https://example.com/upstream.git"},
			{"branch.main.remote", "upstream"},
		}},
		{name: "only remote", config: [][2]string{{"remote.fork.url", "https://example.com/fork.git"}}},
		{name: "no origin among several", config: [][2]string{
			{"remote.a.url", "https://example.com/a.git"},
			{"remote.b.url", "https://example.com/b.git"},
		}},
		{name: "longest insteadOf", config: [][2]string{
			{"remote.origin.url", "work:team/repo.git"},
			{"url.https://short.example/.insteadOf", "work:"},
			{"url.https://long.example/team/.insteadOf", "work:team/"},
		}},
		{name: "no remote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newGitFixture(t)
			for _, kv := range tt.config {
				f.git("config", kv[0], kv[1])
			}
			got, err := gitRemoteURL(t.Context(), f.path)
			cmd := exec.Command("git", "-C", f.path, "ls-remote", "--get-url")
			cmd.Env = gitConfigIsolationEnv()
			want, gitErr := cmd.Output()
			if gitErr != nil {
				require.ErrorIs(t, err, errNoGitRemote)
				return
			}
			require.NoError(t, err)
			require.Equal(t, string(bytes.TrimSpace(want)), got)
		})
	}
}

func TestGitPathQuoting(t *testing.T) {
	sep := string(os.PathListSeparator)
	paths, err := splitGitPathList(`/a` + sep + `"/b` + sep + `c\"d"` + sep + sep + `/e`)
	require.NoError(t, err)
	require.Equal(t, []string{"/a", "/b" + sep + `c"d`, "/e"}, paths)
	_, err = splitGitPathList(`"/unterminated`)
	require.Error(t, err)

	require.Equal(t, "/plain path", quoteGitPath("/plain path"))
	require.Equal(t, `"#a\\b\"c"`, quoteGitPath(`#a\b"c`))
	require.Equal(t, `"/a\012b"`, quoteGitPath("/a\nb"))
}
