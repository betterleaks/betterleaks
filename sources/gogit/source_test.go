//nolint:exhaustruct // Test fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/sources"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/storage/memory"
	"github.com/stretchr/testify/require"
)

func gitFixture(t *testing.T, repo string, args ...string) string {
	t.Helper()
	binary, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git fixture generator unavailable")
	}
	cmd := exec.Command(binary, append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
	return strings.TrimSpace(string(out))
}
func newHistory(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	gitFixture(t, repo, "config", "user.name", "First Author")
	gitFixture(t, repo, "config", "user.email", "first@example.test")
	write := func(name, text string) {
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(text), 0644))
	}
	commit := func(message, date string) {
		gitFixture(t, repo, "add", ".")
		gitFixture(t, repo, "-c", "user.name="+message, "commit", "-qm", message, "--date", date)
	}
	write("file.txt", "first\nTOKEN_ROOT\nlast\n")
	commit("root", "2001-01-01T00:00:00Z")
	root := gitFixture(t, repo, "rev-parse", "HEAD")
	write("file.txt", "first\nTOKEN_CHANGED\nlast\n")
	commit("modify", "2001-01-02T00:00:00Z")
	gitFixture(t, repo, "mv", "file.txt", "renamed.txt")
	commit("rename", "2001-01-03T00:00:00Z")
	gitFixture(t, repo, "checkout", "-qb", "side", root)
	write("side.txt", "TOKEN_SIDE\n")
	commit("side", "2001-01-04T00:00:00Z")
	gitFixture(t, repo, "checkout", "-q", "main")
	gitFixture(t, repo, "merge", "--no-ff", "side", "-qm", "merge")
	// Local diff helpers and hooks must never execute during object reads.
	write(".gitattributes", "*.txt diff=evil\n")
	commit("attributes", "2001-01-05T00:00:00Z")
	marker := filepath.Join(repo, "executed")
	gitFixture(t, repo, "config", "diff.evil.textconv", "touch "+marker)
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "hooks", "post-checkout"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0755))
	return repo
}
func collect(t *testing.T, s *Source) []sources.Fragment {
	t.Helper()
	var mu sync.Mutex
	var fragments []sources.Fragment
	require.NoError(t, s.Fragments(t.Context(), func(f sources.Fragment, err error) error {
		require.NoError(t, err)
		mu.Lock()
		defer mu.Unlock()
		fragments = append(fragments, f)
		return nil
	}))
	return fragments
}
func textOccurrences(fs []sources.Fragment) map[string]string {
	result := map[string]string{}
	for _, f := range fs {
		if strings.Contains(f.Raw, "TOKEN_") {
			result[f.Raw] = fmt.Sprintf("%s:%d", f.Attr(sources.AttrPath), f.StartLine)
		}
	}
	return result
}

func TestSource(t *testing.T) {
	repo := newHistory(t)
	expected := map[string]string{"first\nTOKEN_ROOT\nlast\n": "file.txt:1", "TOKEN_CHANGED\n": "file.txt:2", "TOKEN_SIDE\n": "side.txt:1"}
	for _, packed := range []bool{false, true} {
		if packed {
			gitFixture(t, repo, "repack", "-ad")
		}
		t.Run(fmt.Sprintf("packed=%v", packed), func(t *testing.T) {
			t.Setenv("PATH", t.TempDir())
			for _, workers := range []int{1, 4} {
				fs := collect(t, &Source{RepoPath: repo, Workers: workers})
				require.Equal(t, expected, textOccurrences(fs))
				for _, f := range fs {
					require.Len(t, f.Attr(sources.AttrGitSHA), 40)
					require.Len(t, f.Attr(sources.AttrGitBlobSHA), 40)
					require.NotEmpty(t, f.Attr(sources.AttrGitAuthorName))
					require.NotEmpty(t, f.Attr(sources.AttrGitCommitterDate))
					require.Equal(t, sources.ResourceGitPatchContent, f.Attr(sources.AttrResource))
				}
			}
			_, err := os.Stat(filepath.Join(repo, "executed"))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}

	t.Run("alternates", func(t *testing.T) {
		shared := filepath.Join(t.TempDir(), "shared")
		gitFixture(t, repo, "clone", "-q", "--shared", repo, shared)
		err := (&Source{RepoPath: shared}).Fragments(t.Context(), func(sources.Fragment, error) error { t.Fatal("yield from external alternate"); return nil })
		require.ErrorIs(t, err, ErrExternalStore)
		require.Equal(t, expected, textOccurrences(collect(t, &Source{RepoPath: shared, AllowExternalObjects: true})))
	})
	t.Run("shallow", func(t *testing.T) {
		// Like git log -p, the boundary commit is compared with an empty tree.
		shallow := filepath.Join(t.TempDir(), "shallow")
		gitFixture(t, repo, "clone", "-q", "--depth=1", "file://"+repo, shallow)
		fs := collect(t, &Source{RepoPath: shallow})
		require.Equal(t, map[string]string{"first\nTOKEN_CHANGED\nlast\n": "renamed.txt:1", "TOKEN_SIDE\n": "side.txt:1"}, textOccurrences(fs))
		boundary := gitFixture(t, shallow, "rev-parse", "HEAD")
		for _, f := range fs {
			require.Equal(t, boundary, f.Attr(sources.AttrGitSHA))
		}
		deeper := filepath.Join(t.TempDir(), "deeper")
		gitFixture(t, repo, "clone", "-q", "--depth=3", "file://"+repo, deeper)
		require.Equal(t, expected["TOKEN_SIDE\n"], textOccurrences(collect(t, &Source{RepoPath: deeper}))["TOKEN_SIDE\n"])
	})
	t.Run("subdirectory", func(t *testing.T) {
		sub := filepath.Join(repo, "sub", "dir")
		require.NoError(t, os.MkdirAll(sub, 0700))
		defer os.RemoveAll(filepath.Join(repo, "sub"))
		require.Equal(t, expected, textOccurrences(collect(t, &Source{RepoPath: sub})))
	})
	t.Run("cancel-slow-consumer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() {
			done <- (&Source{RepoPath: repo, Workers: 4}).Fragments(ctx, func(sources.Fragment, error) error {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return ctx.Err()
			})
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("source did not yield")
		}
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("canceled source did not stop")
		}
	})
	t.Run("prefilter", func(t *testing.T) {
		fs := collect(t, &Source{RepoPath: repo, Prefilter: func(a map[string]string) bool { return a[sources.AttrPath] != "side.txt" }})
		require.Equal(t, map[string]string{"TOKEN_SIDE\n": "side.txt:1"}, textOccurrences(fs))
		// Rejected resources must not require content materialization.
		require.Empty(t, collect(t, &Source{RepoPath: repo, MaxBlobBytes: 1, Prefilter: func(map[string]string) bool { return true }}))
	})
	t.Run("author", func(t *testing.T) {
		fs := collect(t, &Source{RepoPath: repo, Author: "modify <"})
		require.Equal(t, map[string]string{"TOKEN_CHANGED\n": "file.txt:2"}, textOccurrences(fs))
	})
	t.Run("messages", func(t *testing.T) {
		fs := collect(t, &Source{RepoPath: repo, Include: []string{"commit-messages"}})
		messages := 0
		for _, f := range fs {
			if f.Attr(sources.AttrResource) == sources.ResourceGitCommitMessage {
				messages++
				require.Empty(t, f.Attr(sources.AttrPath))
			}
		}
		require.Equal(t, 6, messages)
	})
	t.Run("stop", func(t *testing.T) {
		stop := errors.New("consumer stopped")
		err := (&Source{RepoPath: repo, Workers: 4}).Fragments(t.Context(), func(sources.Fragment, error) error { return stop })
		require.ErrorIs(t, err, stop)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, (&Source{RepoPath: repo}).Fragments(ctx, func(sources.Fragment, error) error { t.Fatal("yield after cancellation"); return nil }), context.Canceled)
	})
	t.Run("limits", func(t *testing.T) {
		// Oversized blobs are skipped with a warning, not a yielded error, so
		// the scan still finishes and succeeds.
		var logs bytes.Buffer
		var yielded atomic.Int32
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		err := (&Source{RepoPath: repo, MaxBlobBytes: 1, Logger: logger}).Fragments(t.Context(), func(f sources.Fragment, err error) error {
			if err != nil || f.Attr(sources.AttrPath) != "" {
				yielded.Add(1)
			}
			return nil
		})
		require.NoError(t, err)
		require.Zero(t, yielded.Load(), "every blob in the fixture exceeds one byte")
		require.Contains(t, logs.String(), "skipped Git content over a limit")
		require.Contains(t, logs.String(), "exceeds limit 1")
		for _, bad := range []*Source{
			{RepoPath: repo, Author: "["},
			{RepoPath: repo, Include: []string{"reflog-history"}},
			{RepoPath: repo, Revision: "main...side"},
			{RepoPath: repo, MaxBlobBytes: 5 << 30},
			{RepoPath: repo, Workers: 17},
			{RepoPath: repo, DiskCacheMiB: -1},
		} {
			require.Error(t, bad.Validate())
		}
	})
	t.Run("bare-and-worktree", func(t *testing.T) {
		bare := filepath.Join(t.TempDir(), "bare")
		gitFixture(t, repo, "clone", "-q", "--bare", repo, bare)
		require.Equal(t, expected, textOccurrences(collect(t, &Source{RepoPath: bare})))
		linked := filepath.Join(t.TempDir(), "linked")
		gitFixture(t, repo, "worktree", "add", "--detach", linked, "HEAD")
		// The fixture's hook executed during Git's checkout, not during the scan.
		os.Remove(filepath.Join(repo, "executed"))
		require.Equal(t, expected, textOccurrences(collect(t, &Source{RepoPath: linked})))
		_, err := os.Stat(filepath.Join(repo, "executed"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestHistoricalPathNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture contains a literal backslash filename")
	}
	repo := newHistory(t)
	old := strings.Repeat("common line\n", 100) + "TOKEN_BEFORE\n"
	require.NoError(t, os.WriteFile(filepath.Join(repo, "before"), []byte(old), 0600))
	gitFixture(t, repo, "add", "before")
	gitFixture(t, repo, "commit", "-qm", "before historical rename")
	name := "\\"
	gitFixture(t, repo, "mv", "before", name)
	require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(strings.Repeat("common line\n", 100)+"TOKEN_AFTER\n"), 0600))
	gitFixture(t, repo, "add", "--", name)
	gitFixture(t, repo, "commit", "-qm", "historical rename")
	fs := collect(t, &Source{RepoPath: repo, MaxCount: 1})
	require.Len(t, fs, 1)
	require.Equal(t, name, fs[0].Attr(sources.AttrPath))
	require.Equal(t, "TOKEN_AFTER\n", fs[0].Raw)
	require.Equal(t, 101, fs[0].StartLine)
}

func TestSelectionAndArchives(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	gitFixture(t, repo, "config", "user.name", "Test")
	gitFixture(t, repo, "config", "user.email", "test@example.test")
	commit := func(text, date string) {
		require.NoError(t, os.WriteFile(filepath.Join(repo, "file"), []byte(text), 0644))
		gitFixture(t, repo, "add", ".")
		gitFixture(t, repo, "-c", "user.name=Date Author", "commit", "-qm", text, "--date", date)
		// Set committer time independently of author time using a fixture process.
		cmd := exec.Command("git", "-C", repo, "commit", "--amend", "--no-edit", "--quiet")
		cmd.Env = append(os.Environ(), "GIT_COMMITTER_DATE="+date)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
	}
	commit("TOKEN_OLD\n", "2001-01-01T00:00:00Z")
	commit("TOKEN_NEW\n", "2001-01-03T00:00:00Z")
	date := time.Date(2001, 1, 2, 0, 0, 0, 0, time.UTC)
	require.Equal(t, map[string]string{"TOKEN_NEW\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Since: &date})))
	require.Equal(t, map[string]string{"TOKEN_OLD\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Until: &date})))
	require.Equal(t, map[string]string{"TOKEN_NEW\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, MaxCount: 1})))
	zipFile, err := os.Create(filepath.Join(repo, "archive.zip"))
	require.NoError(t, err)
	writer := zip.NewWriter(zipFile)
	inner, err := writer.Create("secret.txt")
	require.NoError(t, err)
	_, err = inner.Write([]byte("TOKEN_ARCHIVE\n"))
	require.NoError(t, err)
	// A malformed nested archive must not discard readable siblings or fail
	// the Git scan. GitLab's registry fixture contains this empty-ZIP case.
	_, err = writer.Create("empty.zip")
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, zipFile.Close())
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err = gz.Write([]byte("TOKEN_GZIP\n"))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	data := compressed.Bytes()
	data[len(data)-8] ^= 0xff // corrupt CRC, keeping the contents readable
	require.NoError(t, os.WriteFile(filepath.Join(repo, "corrupt.gz"), data, 0600))
	gitFixture(t, repo, "add", ".")
	gitFixture(t, repo, "commit", "-qm", "archive")
	var warnings bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&warnings, nil))
	fs := collect(t, &Source{RepoPath: repo, MaxCount: 1, MaxArchiveDepth: 2, Logger: logger})
	require.Equal(t, map[string]string{
		"TOKEN_ARCHIVE\n": "archive.zip!secret.txt:1",
		"TOKEN_GZIP\n":    "corrupt.gz:1",
	}, textOccurrences(fs))
	require.Contains(t, warnings.String(), "level=WARN")
	require.Contains(t, warnings.String(), "archive.zip!empty.zip")
	require.Contains(t, warnings.String(), "gzip: invalid checksum")
}

func TestSHA256(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "--object-format=sha256")
	gitFixture(t, repo, "config", "user.name", "Test")
	gitFixture(t, repo, "config", "user.email", "test@example.test")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret"), []byte("TOKEN_SHA256\n"), 0644))
	gitFixture(t, repo, "add", ".")
	gitFixture(t, repo, "commit", "-qm", "root")
	gitFixture(t, repo, "repack", "-ad")
	fs := collect(t, &Source{RepoPath: repo})
	require.Len(t, fs, 1)
	require.Len(t, fs[0].Attr(sources.AttrGitBlobSHA), 64)
	require.Len(t, fs[0].Attr(sources.AttrGitSHA), 64)
	root := gitFixture(t, repo, "rev-parse", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret"), []byte("ABANDONED_SHA256\n"), 0644))
	gitFixture(t, repo, "add", ".")
	gitFixture(t, repo, "commit", "-qm", "abandoned")
	gitFixture(t, repo, "reset", "--hard", root)
	gitFixture(t, repo, "notes", "add", "-m", "NOTE_SHA256")
	t.Setenv("PATH", t.TempDir())
	fs = collect(t, &Source{RepoPath: repo, Include: []string{"reflogs", "notes"}})
	var abandoned, messages, note bool
	for _, f := range fs {
		abandoned = abandoned || f.Raw == "ABANDONED_SHA256\n"
		if f.Attr(sources.AttrResource) == sources.ResourceGitNote {
			note = true
			require.Equal(t, "NOTE_SHA256\n", f.Raw)
			require.Equal(t, root, f.Attr("git.note_target"))
		}
		if f.Attr(sources.AttrResource) == sources.ResourceGitReflogMessage {
			messages = true
			require.Len(t, f.Attr("git.reflog_old_sha"), 64)
			require.Len(t, f.Attr("git.reflog_new_sha"), 64)
		}
	}
	require.True(t, abandoned)
	require.True(t, messages)
	require.True(t, note)
}

// A timestamp walk can encounter a shared first parent while another merge
// parent remains queued. Stopping at the shared parent loses that entire branch.
func TestAllHistoryCoverage(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			repo := t.TempDir()
			gitFixture(t, repo, "init", "-q", "-b", "main", "--object-format="+format)
			gitFixture(t, repo, "config", "user.name", "Test")
			gitFixture(t, repo, "config", "user.email", "test@example.test")
			require.NoError(t, os.WriteFile(filepath.Join(repo, "secret"), []byte("TOKEN_HISTORY\n"), 0644))
			gitFixture(t, repo, "add", ".")
			tree := gitFixture(t, repo, "write-tree")
			commit := func(message, date string, parents ...string) string {
				t.Helper()
				args := []string{"-C", repo, "commit-tree", tree, "-m", message}
				for _, parent := range parents {
					args = append(args, "-p", parent)
				}
				cmd := exec.Command("git", args...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
				raw, err := cmd.CombinedOutput()
				require.NoError(t, err, "%s", raw)
				return strings.TrimSpace(string(raw))
			}
			root := commit("root", "2000-01-01T00:00:00Z")
			shared := commit("shared", "2030-01-01T00:00:00Z", root)
			side := commit("side", "2010-01-01T00:00:00Z", root)
			merge := commit("merge", "2020-01-01T00:00:00Z", shared, side)
			orphan := commit("tag-only", "2005-01-01T00:00:00Z")
			gitFixture(t, repo, "update-ref", "refs/heads/main", shared)
			gitFixture(t, repo, "update-ref", "refs/heads/other", merge)
			gitFixture(t, repo, "update-ref", "refs/remotes/origin/main", shared)
			gitFixture(t, repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
			gitFixture(t, repo, "tag", "-a", "release", orphan, "-m", "tag")
			gitFixture(t, repo, "tag", "-a", "nested", "release", "-m", "nested tag")
			gitFixture(t, repo, "repack", "-ad")
			expected := strings.Fields(gitFixture(t, repo, "rev-list", "--all"))
			messages := func(s *Source) map[string]int {
				s.Include = []string{sources.GitResourceTypeCommitMessages}
				result := map[string]int{}
				for _, f := range collect(t, s) {
					if f.Attr(sources.AttrResource) == sources.ResourceGitCommitMessage {
						result[f.Attr(sources.AttrGitSHA)]++
					}
				}
				return result
			}
			actual := messages(&Source{RepoPath: repo})
			require.Len(t, actual, len(expected))
			for _, sha := range expected {
				require.Equal(t, 1, actual[sha], "missing or repeated commit %s", sha)
			}
			require.Contains(t, actual, side)
			require.Contains(t, actual, orphan)
			limited := messages(&Source{RepoPath: repo, MaxCount: 1})
			require.Equal(t, map[string]int{shared: 1}, limited)
			since := time.Date(2009, 1, 1, 0, 0, 0, 0, time.UTC)
			selected := messages(&Source{RepoPath: repo, Since: &since})
			require.Equal(t, map[string]int{side: 1, merge: 1, shared: 1}, selected)
			// Invalid refs must not be quietly skipped as upstream's All iterator does.
			missing := strings.Repeat("1", len(root))
			gitFixture(t, repo, "update-ref", "refs/heads/broken", root)
			require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "refs", "heads", "broken"), []byte(missing+"\n"), 0644))
			err := (&Source{RepoPath: repo}).Fragments(t.Context(), func(sources.Fragment, error) error { return nil })
			require.ErrorContains(t, err, "broken")
			gitFixture(t, repo, "update-ref", "-d", "refs/heads/broken")
			// A syntactically valid commit can still name an unavailable parent.
			// Report the gap rather than treating it as the end of that ref's walk.
			raw := "tree " + tree + "\nparent " + missing + "\nauthor Test <test@example.test> 0 +0000\ncommitter Test <test@example.test> 0 +0000\n\nincomplete history\n"
			write := exec.Command("git", "-C", repo, "hash-object", "-t", "commit", "-w", "--stdin")
			write.Stdin = strings.NewReader(raw)
			written, err := write.CombinedOutput()
			require.NoError(t, err, "%s", written)
			gitFixture(t, repo, "update-ref", "refs/heads/incomplete", strings.TrimSpace(string(written)))
			err = (&Source{RepoPath: repo}).Fragments(t.Context(), func(sources.Fragment, error) error { return nil })
			require.ErrorContains(t, err, "parent "+missing)
		})
	}
}

// Set BETTERLEAKS_GIT_BENCH_REPO to an absolute fixture path. No detector or
// tree traversal runs here, making graph retention and startup costs visible.
func BenchmarkHistory(b *testing.B) {
	path := os.Getenv("BETTERLEAKS_GIT_BENCH_REPO")
	if path == "" {
		b.Skip("set BETTERLEAKS_GIT_BENCH_REPO")
	}
	b.ReportAllocs()
	for range b.N {
		s := &Source{RepoPath: path}
		r, cleanup, err := s.open(b.Context())
		if err != nil {
			b.Fatal(err)
		}
		h, err := s.history(b.Context(), r)
		if err != nil {
			cleanup()
			b.Fatal(err)
		}
		n, frontier := 0, 0
		for {
			_, err := h.next(b.Context())
			if err == io.EOF {
				break
			}
			if err != nil {
				cleanup()
				b.Fatal(err)
			}
			n++
			frontier = max(frontier, len(h.frontier))
		}
		cleanup()
		b.ReportMetric(float64(n), "commits/op")
		b.ReportMetric(float64(frontier), "frontier/op")
	}
}

func TestUnreachableBlobsAndNotesWithoutGit(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	gitFixture(t, repo, "config", "user.name", "Note Author")
	gitFixture(t, repo, "config", "user.email", "notes@example.test")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "file"), []byte("COMMITTED_SECRET\n"), 0600))
	gitFixture(t, repo, "add", "file")
	gitFixture(t, repo, "commit", "-qm", "MESSAGE_SECRET")
	target := gitFixture(t, repo, "rev-parse", "HEAD")
	gitFixture(t, repo, "notes", "add", "-m", "NOTE_OLD_SECRET")
	firstNoteCommit := gitFixture(t, repo, "rev-parse", "refs/notes/commits")
	gitFixture(t, repo, "notes", "add", "-f", "-m", "NOTE_NEW_SECRET")
	gitFixture(t, repo, "notes", "remove", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "uncommitted"), []byte("LOOSE_SECRET\n"), 0600))
	gitFixture(t, repo, "add", "uncommitted")
	looseID := gitFixture(t, repo, "rev-parse", ":uncommitted")
	gitFixture(t, repo, "reset", "-q", "HEAD", "uncommitted")
	require.NoError(t, os.Remove(filepath.Join(repo, "uncommitted")))
	t.Setenv("PATH", t.TempDir())
	fs := collect(t, &Source{RepoPath: repo, Include: []string{"commit-messages", "notes", "unreachable-objects"}})
	var notes []string
	var blobs, patches, messages int
	for _, f := range fs {
		switch f.Attr(sources.AttrResource) {
		case sources.ResourceGitNote:
			notes = append(notes, f.Raw)
			require.Equal(t, target, f.Attr("git.note_target"))
			require.Equal(t, "refs/notes/commits", f.Attr("git.notes_ref"))
			require.Empty(t, f.Attr(sources.AttrPath))
			require.Empty(t, f.Attr(sources.AttrGitRemoteURL))
			if f.Raw == "NOTE_OLD_SECRET\n" {
				require.Equal(t, firstNoteCommit, f.Attr(sources.AttrGitSHA))
			}
		case sources.ResourceGitBlob:
			blobs++
			require.Equal(t, "LOOSE_SECRET\n", f.Raw)
			require.Equal(t, looseID, f.Attr(sources.AttrGitBlobSHA))
			require.Empty(t, f.Attr(sources.AttrGitSHA))
			require.Empty(t, f.Attr(sources.AttrPath))
		case sources.ResourceGitPatchContent:
			patches++
		case sources.ResourceGitCommitMessage:
			messages++
		}
	}
	require.ElementsMatch(t, []string{"NOTE_OLD_SECRET\n", "NOTE_NEW_SECRET\n"}, notes)
	require.Equal(t, 1, blobs)
	require.Equal(t, 1, patches)
	require.Equal(t, 1, messages)
	fs = collect(t, &Source{RepoPath: repo})
	require.Len(t, fs, 1)
	require.Equal(t, "COMMITTED_SECRET\n", fs[0].Raw)
	stop := errors.New("stop loose")
	err := (&Source{RepoPath: repo, Include: []string{"unreachable-objects"}, Prefilter: func(a map[string]string) bool { return a[sources.AttrResource] != sources.ResourceGitBlob }}).Fragments(t.Context(), func(sources.Fragment, error) error { return stop })
	require.ErrorIs(t, err, stop)
}

func TestUnbornLooseArchive(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("secret.txt")
	require.NoError(t, err)
	_, err = io.WriteString(entry, "LOOSE_ARCHIVE_SECRET\n")
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	name := filepath.Join(repo, "no-extension")
	require.NoError(t, os.WriteFile(name, archive.Bytes(), 0600))
	id := gitFixture(t, repo, "hash-object", "-w", name)
	require.NoError(t, os.Remove(name))
	t.Setenv("PATH", t.TempDir())
	fs := collect(t, &Source{RepoPath: repo, Include: []string{"unreachable-objects"}, MaxArchiveDepth: 1})
	require.Len(t, fs, 1)
	require.Equal(t, "LOOSE_ARCHIVE_SECRET\n", fs[0].Raw)
	require.Equal(t, sources.ResourceGitBlob, fs[0].Attr(sources.AttrResource))
	require.Equal(t, id, fs[0].Attr(sources.AttrGitBlobSHA))
	require.Contains(t, fs[0].Attr(sources.AttrPath), "secret.txt")
	require.Empty(t, fs[0].Attr(sources.AttrGitSHA))
	err = (&Source{RepoPath: repo, Revision: "missing"}).Fragments(t.Context(), func(sources.Fragment, error) error { return nil })
	require.ErrorContains(t, err, "resolve revision")
}

func TestPackedNotesInWorktree(t *testing.T) {
	repo := newHistory(t)
	gitFixture(t, repo, "notes", "--ref=review", "add", "-m", "PACKED_NOTE_SECRET")
	gitFixture(t, repo, "gc")
	worktree := filepath.Join(t.TempDir(), "worktree")
	gitFixture(t, repo, "worktree", "add", "--detach", worktree)
	name := filepath.Join(worktree, "uncommitted")
	require.NoError(t, os.WriteFile(name, []byte("WORKTREE_LOOSE_SECRET\n"), 0600))
	id := gitFixture(t, worktree, "hash-object", "-w", name)
	t.Setenv("PATH", t.TempDir())
	fs := collect(t, &Source{RepoPath: worktree, Include: []string{"notes", "unreachable-objects"}, Prefilter: func(a map[string]string) bool {
		return a[sources.AttrResource] == sources.ResourceGitPatchContent
	}})
	require.Len(t, fs, 2)
	for _, f := range fs {
		switch f.Attr(sources.AttrResource) {
		case sources.ResourceGitNote:
			require.Equal(t, "PACKED_NOTE_SECRET\n", f.Raw)
			require.Equal(t, "refs/notes/review", f.Attr("git.notes_ref"))
		case sources.ResourceGitBlob:
			require.Equal(t, "WORKTREE_LOOSE_SECRET\n", f.Raw)
			require.Equal(t, id, f.Attr(sources.AttrGitBlobSHA))
		default:
			t.Fatalf("unexpected resource %q", f.Attr(sources.AttrResource))
		}
	}
}

func TestGitResourceSelection(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	gitFixture(t, repo, "config", "user.name", "Resource Test")
	gitFixture(t, repo, "config", "user.email", "test@example.test")
	file := filepath.Join(repo, "file")
	require.NoError(t, os.WriteFile(file, []byte("HISTORY_SECRET\n"), 0600))
	gitFixture(t, repo, "add", "file")
	gitFixture(t, repo, "commit", "-qm", "MESSAGE_SECRET")
	gitFixture(t, repo, "notes", "add", "-m", "NOTE_SECRET")
	// Exercise packed reachable content alongside a loose unreachable blob.
	gitFixture(t, repo, "gc")
	require.NoError(t, os.WriteFile(file, []byte("LOOSE_SECRET\n"), 0600))
	gitFixture(t, repo, "hash-object", "-w", file)
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		name             string
		include, exclude []string
		want             []string
	}{
		{"default", nil, nil, []string{"HISTORY_SECRET\n"}},
		{"explicit default", []string{"history"}, nil, []string{"HISTORY_SECRET\n"}},
		{"add messages", []string{"commit-messages"}, nil, []string{"HISTORY_SECRET\n", "MESSAGE_SECRET\n"}},
		{"add notes", []string{"notes"}, nil, []string{"HISTORY_SECRET\n", "NOTE_SECRET\n"}},
		{"add unreachable", []string{"unreachable-objects"}, nil, []string{"HISTORY_SECRET\n", "LOOSE_SECRET\n"}},
		{"everything", []string{"notes", "commit-messages", "unreachable-objects"}, nil, []string{"HISTORY_SECRET\n", "LOOSE_SECRET\n", "MESSAGE_SECRET\n", "NOTE_SECRET\n"}},
		{"exclude optional resources", nil, []string{"objects", "unreachable-objects", "commit-messages", "notes"}, []string{"HISTORY_SECRET\n"}},
		{"messages only", []string{"commit-messages"}, []string{"history"}, []string{"MESSAGE_SECRET\n"}},
		{"notes only", []string{"notes"}, []string{"history"}, []string{"NOTE_SECRET\n"}},
		{"messages and notes", []string{"commit-messages", "notes"}, []string{"history"}, []string{"MESSAGE_SECRET\n", "NOTE_SECRET\n"}},
		{"unreachable only", []string{"unreachable-objects"}, []string{"history"}, []string{"LOOSE_SECRET\n"}},
		{"objects only", []string{"objects"}, []string{"history"}, []string{"HISTORY_SECRET\n", "NOTE_SECRET\n", "LOOSE_SECRET\n"}},
		{"objects subsume unreachable", []string{"objects", "unreachable-objects"}, []string{"history"}, []string{"HISTORY_SECRET\n", "NOTE_SECRET\n", "LOOSE_SECRET\n"}},
		{"objects independent of unreachable exclusion", []string{"objects"}, []string{"history", "unreachable-objects"}, []string{"HISTORY_SECRET\n", "NOTE_SECRET\n", "LOOSE_SECRET\n"}},
		{"objects plus history", []string{"objects"}, nil, []string{"HISTORY_SECRET\n", "HISTORY_SECRET\n", "NOTE_SECRET\n", "LOOSE_SECRET\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, f := range collect(t, &Source{RepoPath: repo, Include: tc.include, Exclude: tc.exclude}) {
				got = append(got, f.Raw)
			}
			require.ElementsMatch(t, tc.want, got)
		})
	}
	for _, s := range []Source{
		{Include: []string{"unknown"}}, {Exclude: []string{"unknown"}},
		{Include: []string{""}}, {Exclude: []string{""}},
		{Exclude: []string{"history"}},
		{Exclude: []string{"history", "notes", "commit-messages"}},
	} {
		s.RepoPath = repo
		require.Error(t, s.Validate())
	}
	for _, resource := range []string{"history", "merges", "objects", "unreachable-objects", "notes", "commit-messages", "tag-messages", "reflogs"} {
		s := &Source{RepoPath: repo, Include: []string{resource}, Exclude: []string{resource}}
		require.ErrorContains(t, s.Validate(), "both included and excluded")
	}
}

func TestExcludedGitResourcesAreNotRead(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q", "-b", "main")
	gitFixture(t, repo, "config", "user.name", "Resource Test")
	gitFixture(t, repo, "config", "user.email", "test@example.test")
	file := filepath.Join(repo, "file")
	require.NoError(t, os.WriteFile(file, []byte("LOOSE_SECRET\n"), 0600))
	gitFixture(t, repo, "add", "file")
	gitFixture(t, repo, "commit", "-qm", "MESSAGE_SECRET")
	gitFixture(t, repo, "notes", "add", "-m", "NOTE_SECRET")
	treeID := gitFixture(t, repo, "rev-parse", "HEAD^{tree}")
	commitID := gitFixture(t, repo, "rev-parse", "HEAD")
	t.Setenv("PATH", t.TempDir())
	// Messages need commits but not their trees or file blobs.
	require.NoError(t, os.Remove(filepath.Join(repo, ".git", "objects", treeID[:2], treeID[2:])))
	messages := &Source{RepoPath: repo, Include: []string{"commit-messages"}, Exclude: []string{"history"}}
	fs := collect(t, messages)
	require.Len(t, fs, 1)
	require.Equal(t, "MESSAGE_SECRET\n", fs[0].Raw)
	stop := errors.New("consumer stopped")
	require.ErrorIs(t, messages.Fragments(t.Context(), func(sources.Fragment, error) error { return stop }), stop)
	err := (&Source{RepoPath: repo}).Fragments(t.Context(), func(sources.Fragment, error) error { return nil })
	require.Error(t, err, "history would need the removed tree")
	// Neither notes nor all-object scans need the ordinary HEAD commit.
	require.NoError(t, os.Remove(filepath.Join(repo, ".git", "objects", commitID[:2], commitID[2:])))
	fs = collect(t, &Source{RepoPath: repo, Include: []string{"notes"}, Exclude: []string{"history"}})
	require.Len(t, fs, 1)
	require.Equal(t, "NOTE_SECRET\n", fs[0].Raw)
	fs = collect(t, &Source{RepoPath: repo, Include: []string{"objects"}, Exclude: []string{"history"}})
	var raw []string
	for _, f := range fs {
		raw = append(raw, f.Raw)
	}
	require.ElementsMatch(t, []string{"LOOSE_SECRET\n", "NOTE_SECRET\n"}, raw)
	err = (&Source{RepoPath: repo, Include: []string{"unreachable-objects"}, Exclude: []string{"history"}}).Fragments(t.Context(), func(sources.Fragment, error) error { return nil })
	require.ErrorContains(t, err, "missing from object inventory", "broken reachability must not turn reachable blobs into unreachable ones")
}

func TestObjectScanCancellationAndLinks(t *testing.T) {
	repo := t.TempDir()
	gitFixture(t, repo, "init", "-q")
	file := filepath.Join(repo, "file")
	require.NoError(t, os.WriteFile(file, []byte("OBJECT_SECRET\n"), 0600))
	id := gitFixture(t, repo, "hash-object", "-w", file)
	t.Setenv("PATH", t.TempDir())
	for _, resource := range []string{"objects", "unreachable-objects"} {
		s := &Source{RepoPath: repo, Include: []string{resource}, Exclude: []string{"history"}}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, s.Fragments(ctx, func(sources.Fragment, error) error { t.Fatal("yield after cancellation"); return nil }), context.Canceled)
		stop := errors.New("stop")
		require.ErrorIs(t, s.Fragments(t.Context(), func(sources.Fragment, error) error { return stop }), stop)
	}
	path := filepath.Join(repo, ".git", "objects", id[:2], id[2:])
	outside := filepath.Join(t.TempDir(), "object")
	require.NoError(t, os.Rename(path, outside))
	require.NoError(t, os.Symlink(outside, path))
	s := &Source{RepoPath: repo, Include: []string{"objects"}, Exclude: []string{"history"}}
	require.ErrorContains(t, s.Fragments(t.Context(), func(sources.Fragment, error) error { t.Fatal("yield from linked object"); return nil }), "not a regular file")
	require.NoError(t, os.Remove(path))
	dir := filepath.Dir(path)
	require.NoError(t, os.Remove(dir))
	require.NoError(t, os.Symlink(filepath.Dir(outside), dir))
	require.ErrorContains(t, s.Fragments(t.Context(), func(sources.Fragment, error) error { t.Fatal("yield from linked object directory"); return nil }), "not a directory")
}

// A tiny DAG represents more than 100,000 file paths, or over a million empty
// directories. Neither may be expanded without a bound merely because its
// unique objects fit in the cache.
func TestTreeExpansionBudget(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			store := memory.NewStorage()
			repo, err := git.Init(store, nil)
			require.NoError(t, err)
			var tree object.Tree
			if !empty {
				blob := store.NewEncodedObject()
				blob.SetType(plumbing.BlobObject)
				id, err := store.SetEncodedObject(blob)
				require.NoError(t, err)
				tree.Entries = []object.TreeEntry{{Name: "secret", Mode: filemode.Regular, Hash: id}}
			}
			var id plumbing.Hash
			for range 21 {
				encoded := store.NewEncodedObject()
				require.NoError(t, tree.Encode(encoded))
				id, err = store.SetEncodedObject(encoded)
				require.NoError(t, err)
				tree.Entries = []object.TreeEntry{{Name: "a", Mode: filemode.Dir, Hash: id}, {Name: "b", Mode: filemode.Dir, Hash: id}}
			}
			changes, err := rawTreeChanges(t.Context(), &treeCache{r: repo}, &object.Commit{TreeHash: id}, plumbing.ZeroHash)
			require.True(t, isLimit(err), "%v", err)
			require.Empty(t, changes, "an incomplete comparison must not yield partial patches")
		})
	}
}
