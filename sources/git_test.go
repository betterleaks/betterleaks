package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
)

func TestGitRepoJobsHaveSameCoverage(t *testing.T) {
	repo := newGitTestRepo(t, 4)

	scan := func(jobs int) []string {
		t.Helper()
		var (
			mu        sync.Mutex
			fragments []string
		)
		source := &Git{RepoPath: repo, Jobs: jobs}
		require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
			if err != nil {
				return err
			}
			mu.Lock()
			fragments = append(fragments, fmt.Sprintf("%s:%s:%s",
				fragment.Attr(AttrGitSHA), fragment.Attr(AttrPath), fragment.Raw))
			mu.Unlock()
			return nil
		}))
		sort.Strings(fragments)
		return fragments
	}

	require.Equal(t, scan(1), scan(2))
}

func TestGitRepoDefaultProcessesFragmentsConcurrently(t *testing.T) {
	if automaticJobs() < 2 {
		t.Skip("automatic Git concurrency is serial when GOMAXPROCS is one")
	}
	repo := newGitTestRepo(t, 4)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	done := make(chan error, 1)
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	var active atomic.Int64
	go func() {
		done <- (&Git{RepoPath: repo}).Fragments(t.Context(), func(_ Fragment, err error) error {
			if err != nil {
				return err
			}
			active.Add(1)
			started <- struct{}{}
			<-release
			active.Add(-1)
			return nil
		})
	}()

	for range 2 {
		select {
		case <-started:
		case err := <-done:
			require.NoError(t, err)
			t.Fatal("Git scan completed before yielding concurrent fragments")
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent Git fragments")
		}
	}
	require.GreaterOrEqual(t, active.Load(), int64(2))

	releaseAll()
	require.NoError(t, <-done)
}

func TestGitRepoOneJobConsumesFragmentsSerially(t *testing.T) {
	repo := newGitTestRepo(t, 4)
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	done := make(chan error, 1)
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	var active atomic.Int64
	go func() {
		done <- (&Git{RepoPath: repo, Jobs: 1}).Fragments(t.Context(), func(_ Fragment, err error) error {
			if err != nil {
				return err
			}
			active.Add(1)
			started <- struct{}{}
			<-release
			active.Add(-1)
			return nil
		})
	}()

	select {
	case <-started:
	case err := <-done:
		require.NoError(t, err)
		t.Fatal("Git scan completed before yielding a fragment")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first Git fragment")
	}

	select {
	case <-started:
		t.Fatal("single-worker Git history scan yielded fragments concurrently")
	case <-time.After(100 * time.Millisecond):
	}
	require.Equal(t, int64(1), active.Load())

	releaseAll()
	require.NoError(t, <-done)
}

func newGitTestRepo(t *testing.T, commits int) string {
	t.Helper()
	repo := t.TempDir()
	runGitTestCommand(t, repo, "init", "--quiet")
	runGitTestCommand(t, repo, "config", "user.email", "test@example.com")
	runGitTestCommand(t, repo, "config", "user.name", "Test User")
	for i := range commits {
		path := filepath.Join(repo, fmt.Sprintf("file-%d.txt", i))
		require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("value-%d\n", i)), 0o600))
		runGitTestCommand(t, repo, "add", ".")
		runGitTestCommand(t, repo, "commit", "--quiet", "-m", fmt.Sprintf("commit %d", i))
	}
	return repo
}

func runGitTestCommand(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmdArgs := append([]string{"-C", repo}, args...)
	output, err := exec.Command("git", cmdArgs...).CombinedOutput()
	require.NoError(t, err, string(output))
}

func TestGitCancellationPreservesPendingStderr(t *testing.T) {
	producerErr := errors.New("git stderr")
	workerErr := errors.New("fragment worker")
	g, groupCtx := errgroup.WithContext(t.Context())
	g.Go(func() error { return workerErr })
	<-groupCtx.Done()

	diffFilesCh := make(chan *gitdiff.File)
	errCh := make(chan error)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		diffFilesCh <- &gitdiff.File{}
		close(diffFilesCh)
		errCh <- producerErr
		close(errCh)
	}()

	err := waitForGitWorkers(g, groupCtx, drainGitOutput(diffFilesCh, errCh))
	require.ErrorIs(t, err, producerErr)
	require.ErrorIs(t, err, workerErr)
	<-producerDone
}

func TestWaitForGitWorkersOmitsGroupCancellation(t *testing.T) {
	workerErr := errors.New("fragment worker")
	g, groupCtx := errgroup.WithContext(t.Context())
	g.Go(func() error { return workerErr })
	<-groupCtx.Done()

	err := waitForGitWorkers(g, groupCtx, nil)
	require.ErrorIs(t, err, workerErr)
	require.False(t, errors.Is(err, context.Canceled))
}

func TestWaitForGitWorkersReturnsGroupCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	g, groupCtx := errgroup.WithContext(ctx)
	cancel()
	<-groupCtx.Done()

	require.ErrorIs(t, waitForGitWorkers(g, groupCtx, nil), context.Canceled)
}

func TestGitStreamMatchesLegacy(t *testing.T) {
	repo := newGitTestRepo(t, 1)
	files := map[string]string{
		"space name.txt":    "first\nsecond\nthird\nfourth\nfifth\nlast\n",
		"quoted\"\t日本語.txt": "old without newline",
		"large.txt":         strings.Repeat("ordinary content\n", 20000),
		"binary.dat":        "\x00\x01\x02",
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600))
	}
	runGitTestCommand(t, repo, "add", ".")
	runGitTestCommand(t, repo, "commit", "-qm", "multiple files\n\ncommit message body")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "space name.txt"), []byte("first\nchanged\nthird\nfourth\nfifth\nlast changed\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "quoted\"\t日本語.txt"), []byte("new without newline"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "large.txt"), []byte(strings.Repeat("x", 200000)+"\n"), 0o600))
	runGitTestCommand(t, repo, "mv", "file-0.txt", "renamed.txt")
	runGitTestCommand(t, repo, "add", ".")
	runGitTestCommand(t, repo, "commit", "-qm", "edits and rename")
	runGitTestCommand(t, repo, "rm", "space name.txt")
	runGitTestCommand(t, repo, "commit", "-qm", "delete")

	for _, opts := range []string{"", "--all -U3", "--all --format=fuller", "--all --format=email", "--all --oneline", "--all --binary"} {
		t.Run(opts, func(t *testing.T) {
			legacy, err := NewGitLogCmdContext(t.Context(), repo, opts)
			require.NoError(t, err)
			collect := func(source *Git) []Fragment {
				var mu sync.Mutex
				var fragments []Fragment
				require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
					if err != nil {
						return err
					}
					mu.Lock()
					fragments = append(fragments, fragment)
					mu.Unlock()
					return nil
				}))
				return fragments
			}
			want := collect(&Git{Cmd: legacy, Jobs: 1})
			got := collect(&Git{RepoPath: repo, LogOpts: opts, Jobs: 1})
			require.Equal(t, want, got)
			if opts == "" {
				require.ElementsMatch(t, want, collect(&Git{RepoPath: repo, Jobs: 2}))
			}
		})
	}
}

func TestGitStreamCallbackFailureStopsCommand(t *testing.T) {
	repo := newGitTestRepo(t, 4)
	want := errors.New("stop scan")
	for _, jobs := range []int{1, 2} {
		err := (&Git{RepoPath: repo, Jobs: jobs}).Fragments(t.Context(), func(Fragment, error) error { return want })
		require.ErrorIs(t, err, want)
	}
}

func TestGitStreamReportsCommandFailure(t *testing.T) {
	repo := newGitTestRepo(t, 1)
	err := (&Git{RepoPath: repo, LogOpts: "invalid-revision", Jobs: 1}).Fragments(t.Context(), func(Fragment, error) error { return nil })
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
}

func TestGitStreamOmitsCleanupSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal exit status")
	}
	for _, withStderr := range []bool{false, true} {
		t.Run(fmt.Sprintf("stderr=%t", withStderr), func(t *testing.T) {
			// Keep Git alive waiting for stdin while the supplied patch fails.
			// This makes the cleanup kill deterministic without sleeps.
			cmd := exec.CommandContext(t.Context(), "git", "hash-object", "--stdin")
			stdin, err := cmd.StdinPipe()
			require.NoError(t, err)
			defer stdin.Close()
			require.NoError(t, cmd.Start())
			stderrErr := errors.New("git stderr")
			errCh := make(chan error, 1)
			if withStderr {
				errCh <- stderrErr
			}
			close(errCh)
			source := &Git{Cmd: &GitCmd{
				cmd: cmd, stdout: strings.NewReader("diff --git malformed\n"), errCh: errCh,
			}}
			err = source.Fragments(t.Context(), func(Fragment, error) error { return nil })
			require.ErrorContains(t, err, "invalid Git file header")
			require.ErrorContains(t, err, "missing filename information")
			require.NotContains(t, err.Error(), "signal:")
			var exitErr *exec.ExitError
			require.False(t, errors.As(err, &exitErr))
			if withStderr {
				require.ErrorIs(t, err, stderrErr)
			} else {
				require.NotContains(t, err.Error(), "\n")
			}
		})
	}
}

func TestGitStreamArchives(t *testing.T) {
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
		var fragments []Fragment
		err := (&Git{RepoPath: repo, Jobs: 1, MaxArchiveDepth: depth}).Fragments(t.Context(), func(fragment Fragment, err error) error {
			fragments = append(fragments, fragment)
			return err
		})
		require.NoError(t, err)
		if depth == 0 {
			require.Empty(t, fragments)
		} else {
			require.Len(t, fragments, 1)
			require.Equal(t, "synthetic archive example\n", fragments[0].Raw)
			require.Equal(t, "archive.zip"+InnerPathSeparator+"inner.txt", fragments[0].Attr(AttrPath))
			require.NotEmpty(t, fragments[0].Attr(AttrGitSHA))
		}
	}
}
