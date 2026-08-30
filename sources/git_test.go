package sources

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
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

// TODO: commenting out this test for now because it's flaky. Alternatives to consider to get this working:
// -- use `git stash` instead of `restore()`

// const repoBasePath = "../../testdata/repos/"

// const expectPath = "../../testdata/expected/"

// func TestGitLog(t *testing.T) {
// 	tests := []struct {
// 		source   string
// 		logOpts  string
// 		expected string
// 	}{
// 		{
// 			source:   filepath.Join(repoBasePath, "small"),
// 			expected: filepath.Join(expectPath, "git", "small.txt"),
// 		},
// 		{
// 			source:   filepath.Join(repoBasePath, "small"),
// 			expected: filepath.Join(expectPath, "git", "small-branch-foo.txt"),
// 			logOpts:  "--all foo...",
// 		},
// 	}

// 	err := moveDotGit("dotGit", ".git")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer func() {
// 		if err = moveDotGit(".git", "dotGit"); err != nil {
// 			t.Fatal(err)
// 		}
// 	}()

// 	for _, tt := range tests {
// 		files, err := git.GitLog(tt.source, tt.logOpts)
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var diffSb strings.Builder
// 		for f := range files {
// 			for _, tf := range f.TextFragments {
// 				diffSb.WriteString(tf.Raw(gitdiff.OpAdd))
// 			}
// 		}

// 		expectedBytes, err := os.ReadFile(tt.expected)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		expected := string(expectedBytes)
// 		if expected != diffSb.String() {
// 			// write string builder to .got file using os.Create
// 			err = os.WriteFile(strings.Replace(tt.expected, ".txt", ".got.txt", 1), []byte(diffSb.String()), 0644)
// 			if err != nil {
// 				t.Error(err)
// 			}
// 			t.Error("expected: ", expected, "got: ", diffSb.String())
// 		}
// 	}
// }

// func TestGitDiff(t *testing.T) {
// 	tests := []struct {
// 		source    string
// 		expected  string
// 		additions string
// 		target    string
// 	}{
// 		{
// 			source:    filepath.Join(repoBasePath, "small"),
// 			expected:  "this line is added\nand another one",
// 			additions: "this line is added\nand another one",
// 			target:    filepath.Join(repoBasePath, "small", "main.go"),
// 		},
// 	}

// 	err := moveDotGit("dotGit", ".git")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer func() {
// 		if err = moveDotGit(".git", "dotGit"); err != nil {
// 			t.Fatal(err)
// 		}
// 	}()

// 	for _, tt := range tests {
// 		noChanges, err := os.ReadFile(tt.target)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		err = os.WriteFile(tt.target, []byte(tt.additions), 0644)
// 		if err != nil {
// 			restore(tt.target, noChanges, t)
// 			t.Error(err)
// 		}

// 		files, err := git.GitDiff(tt.source, false)
// 		if err != nil {
// 			restore(tt.target, noChanges, t)
// 			t.Error(err)
// 		}

// 		for f := range files {
// 			sb := strings.Builder{}
// 			for _, tf := range f.TextFragments {
// 				sb.WriteString(tf.Raw(gitdiff.OpAdd))
// 			}
// 			if sb.String() != tt.expected {
// 				restore(tt.target, noChanges, t)
// 				t.Error("expected: ", tt.expected, "got: ", sb.String())
// 			}
// 		}
// 		restore(tt.target, noChanges, t)
// 	}
// }

// func restore(path string, data []byte, t *testing.T) {
// 	err := os.WriteFile(path, data, 0644)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func moveDotGit(from, to string) error {
// 	repoDirs, err := os.ReadDir("../../testdata/repos")
// 	if err != nil {
// 		return err
// 	}
// 	for _, dir := range repoDirs {
// 		if to == ".git" {
// 			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
// 			if os.IsNotExist(err) {
// 				// dont want to delete the only copy of .git accidentally
// 				continue
// 			}
// 			os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
// 		}
// 		if !dir.IsDir() {
// 			continue
// 		}
// 		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
// 		if os.IsNotExist(err) {
// 			continue
// 		}

// 		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
// 			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
