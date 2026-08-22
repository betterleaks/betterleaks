package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recordingWriteCloser struct {
	bytes.Buffer
	closed   bool
	closeErr error
}

func (w *recordingWriteCloser) Close() error {
	w.closed = true
	return w.closeErr
}

func newGitTestRepo(t *testing.T, commits int) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	repo := t.TempDir()
	runGitTestCommand(t, repo, "init", "-q", "-b", "main")
	for i := range commits {
		name := "a.txt"
		if i%2 == 1 {
			name = "b.txt"
		}
		contents := fmt.Sprintf("commit %d\nsecret-%08d\n", i, i)
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(contents), 0o600))
		runGitTestCommand(t, repo, "add", "--all")
		runGitTestCommand(t, repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", fmt.Sprintf("commit %d", i))
	}
	return repo
}

func runGitTestCommand(t *testing.T, repo string, args ...string) {
	t.Helper()
	gitArgs := append([]string{"-C", repo}, args...)
	cmd := exec.Command("git", gitArgs...)
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git %v: %s", args, output)
}

func collectGitFragments(ctx context.Context, source Source) ([]string, error) {
	var (
		mu  sync.Mutex
		got []string
	)
	err := source.Fragments(ctx, func(fragment *Fragment, err error) error {
		if fragment != nil {
			defer fragment.Release()
		}
		if err != nil {
			return err
		}
		mu.Lock()
		got = append(got, fmt.Sprintf(
			"%s\x00%s\x00%d\x00%s",
			fragment.Attr(AttrGitSHA),
			fragment.Attr(AttrPath),
			fragment.StartLine,
			fragment.Raw,
		))
		mu.Unlock()
		return nil
	})
	slices.Sort(got)
	return got, err
}

func TestParallelGitMatchesSingleGit(t *testing.T) {
	repo := newGitTestRepo(t, 6)

	cmd, err := NewGitLogCmd(t.Context(), repo, "")
	require.NoError(t, err)
	want, err := collectGitFragments(t.Context(), &Git{Cmd: cmd})
	require.NoError(t, err)

	got, err := collectGitFragments(t.Context(), &ParallelGit{RepoPath: repo, Workers: 3})
	require.NoError(t, err)
	require.NotEmpty(t, got)
	require.Equal(t, want, got)
}

func TestParallelGitEmptyRepository(t *testing.T) {
	repo := newGitTestRepo(t, 0)
	got, err := collectGitFragments(t.Context(), &ParallelGit{RepoPath: repo, Workers: 3})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestParallelGitPreservesLogOptionsViaSingleWorker(t *testing.T) {
	repo := newGitTestRepo(t, 4)
	const logOpts = "--all -- a.txt"

	cmd, err := NewGitLogCmd(t.Context(), repo, logOpts)
	require.NoError(t, err)
	want, err := collectGitFragments(t.Context(), &Git{Cmd: cmd})
	require.NoError(t, err)

	got, err := collectGitFragments(t.Context(), &ParallelGit{
		RepoPath: repo,
		Workers:  3,
		LogOpts:  logOpts,
	})
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestStreamGitCommitsUsesContiguousChunks(t *testing.T) {
	repo := newGitTestRepo(t, 5)
	output, err := exec.Command("git", "-C", repo, "rev-list", "--all").Output()
	require.NoError(t, err)
	commits := strings.Fields(string(output))
	require.Len(t, commits, 5)

	workers := []*recordingWriteCloser{{}, {}, {}}
	writers := make([]io.WriteCloser, len(workers))
	for i := range workers {
		writers[i] = workers[i]
	}
	require.NoError(t, streamGitCommits(t.Context(), repo, writers, 2))

	require.Equal(t, commits[:2], strings.Fields(workers[0].String()))
	require.Equal(t, commits[2:4], strings.Fields(workers[1].String()))
	require.Equal(t, commits[4:], strings.Fields(workers[2].String()))
	for _, worker := range workers {
		require.True(t, worker.closed)
	}
}

func TestStreamGitCommitsReturnsWriterCloseError(t *testing.T) {
	repo := newGitTestRepo(t, 1)
	wantErr := errors.New("close failed")
	writer := &recordingWriteCloser{closeErr: wantErr}

	err := streamGitCommits(t.Context(), repo, []io.WriteCloser{writer}, 1)
	require.ErrorIs(t, err, wantErr)
	require.True(t, writer.closed)
}

func TestGitReturnsCommandFailure(t *testing.T) {
	cmd, err := NewGitLogCmd(t.Context(), t.TempDir(), "")
	require.NoError(t, err)

	_, err = collectGitFragments(t.Context(), &Git{Cmd: cmd})
	require.Error(t, err)
	require.ErrorContains(t, err, "exit status")
}

func TestGitCallbackErrorCancelsAndReapsCommand(t *testing.T) {
	repo := newGitTestRepo(t, 20)
	cmd, err := NewGitLogCmd(t.Context(), repo, "")
	require.NoError(t, err)

	wantErr := errors.New("stop")
	done := make(chan error, 1)
	go func() {
		done <- (&Git{Cmd: cmd}).Fragments(context.Background(), func(fragment *Fragment, err error) error {
			if fragment != nil {
				defer fragment.Release()
			}
			if err != nil {
				return err
			}
			return wantErr
		})
	}()

	select {
	case err := <-done:
		require.ErrorIs(t, err, wantErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Git.Fragments hung after callback error")
	}
	// Wait is idempotent and confirms that the child was reaped.
	require.Error(t, cmd.Wait())
}
