package sources

import (
	"archive/zip"
	"bufio"
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
	sourcejobs "github.com/betterleaks/betterleaks/v2/sources/internal/jobs"
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
	if sourcejobs.Automatic() < 2 {
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

func runGitTestCommand(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"-C", repo}, args...)
	output, err := exec.Command("git", cmdArgs...).CombinedOutput()
	require.NoError(t, err, string(output))
	return strings.TrimSpace(string(output))
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
	quotedName := "quoted\"\t日本語.txt"
	if runtime.GOOS == "windows" {
		// Windows forbids quotes and tabs in filenames. Unicode still exercises
		// Git's quoted path output; literal quote/tab parsing is tested in memory.
		quotedName = "quoted 日本語.txt"
	}
	files := map[string]string{
		"space name.txt": "first\nsecond\nthird\nfourth\nfifth\nlast\n",
		quotedName:       "old without newline",
		"large.txt":      strings.Repeat("ordinary content\n", 20000),
		"binary.dat":     "\x00\x01\x02",
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600))
	}
	runGitTestCommand(t, repo, "add", ".")
	runGitTestCommand(t, repo, "commit", "-qm", "multiple files\n\ncommit message body")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "space name.txt"), []byte("first\nchanged\nthird\nfourth\nfifth\nlast changed\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, quotedName), []byte("new without newline"), 0o600))
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

func TestGitCommitMessagesCoverage(t *testing.T) {
	repo := newGitTestRepo(t, 0)
	for _, name := range []string{"one.txt", "two.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte("file content\n"), 0600))
	}
	runGitTestCommand(t, repo, "add", ".")
	message := "subject secret-message\n\n  indented body\ndiff --git a/fake b/fake\ncommit fake\n\n"
	runGitTestCommand(t, repo, "commit", "-q", "--cleanup=verbatim", "-m", message, "--author", "Message Author <message@example.com>", "--date", "2001-02-03T04:05:06+00:00")
	runGitTestCommand(t, repo, "branch", "message-main")
	runGitTestCommand(t, repo, "checkout", "-qb", "message-side")
	runGitTestCommand(t, repo, "commit", "-q", "--allow-empty", "-m", "side message")
	runGitTestCommand(t, repo, "checkout", "-q", "message-main")
	runGitTestCommand(t, repo, "commit", "-q", "--allow-empty", "-m", "empty message")
	runGitTestCommand(t, repo, "merge", "--quiet", "--no-ff", "message-side", "-m", "merge message")

	for _, jobs := range []int{1, 2, 0} {
		for _, test := range []struct {
			name, logOpts             string
			include                   []string
			wantMessages, wantPatches int
		}{
			{name: "default", wantPatches: 2},
			{name: "all", include: []string{GitResourceTypeCommitMessages}, wantMessages: 4, wantPatches: 2},
			{name: "duplicate include", include: []string{GitResourceTypeCommitMessages, GitResourceTypeCommitMessages}, wantMessages: 4, wantPatches: 2},
			{name: "latest merge", logOpts: "--max-count=1 HEAD", include: []string{GitResourceTypeCommitMessages}, wantMessages: 1},
			{name: "no merges", logOpts: "--all --no-merges", include: []string{GitResourceTypeCommitMessages}, wantMessages: 3, wantPatches: 2},
		} {
			t.Run(fmt.Sprintf("jobs=%d/%s", jobs, test.name), func(t *testing.T) {
				var mu sync.Mutex
				var fragments []Fragment
				source := &Git{RepoPath: repo, Jobs: jobs, Include: test.include, LogOpts: test.logOpts}
				require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
					if err != nil {
						return err
					}
					mu.Lock()
					fragments = append(fragments, f)
					mu.Unlock()
					return nil
				}))
				messages := make(map[string]string)
				patches := 0
				for _, f := range fragments {
					if f.Attr(AttrResource) == ResourceGitPatchContent {
						patches++
						continue
					}
					require.Equal(t, ResourceGitCommitMessage, f.Attr(AttrResource))
					require.NotEmpty(t, f.Attr(AttrGitSHA))
					require.NotContains(t, messages, f.Attr(AttrGitSHA), "one message per commit, regardless of changed-file count")
					messages[f.Attr(AttrGitSHA)] = f.Raw
					require.NotContains(t, f.Attributes, AttrPath)
					require.Equal(t, 1, f.StartLine)
					require.Equal(t, f.Raw, f.Attr(AttrGitMessage))
					if strings.HasPrefix(f.Raw, "subject") {
						require.Equal(t, message, f.Raw)
						require.Equal(t, "Message Author", f.Attr(AttrGitAuthorName))
						require.Equal(t, "message@example.com", f.Attr(AttrGitAuthorEmail))
						require.Equal(t, "2001-02-03T04:05:06Z", f.Attr(AttrGitDate))
					}
				}
				require.Len(t, messages, test.wantMessages)
				require.Equal(t, test.wantPatches, patches)
			})
		}
	}
}

func TestGitCommitMessagesFilteringAndStop(t *testing.T) {
	repo := newGitTestRepo(t, 3)
	source := &Git{RepoPath: repo, Jobs: 1, Include: []string{GitResourceTypeCommitMessages}}
	source.ShouldSkip = func(attrs map[string]string) bool { return attrs[AttrResource] == ResourceGitCommitMessage }
	require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
		require.NotEqual(t, ResourceGitCommitMessage, f.Attr(AttrResource))
		return err
	}))
	source.ShouldSkip = nil
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stop := errors.New("stop on message")
	err := source.Fragments(ctx, func(f Fragment, err error) error {
		if f.Attr(AttrResource) == ResourceGitCommitMessage {
			return stop
		}
		return err
	})
	require.ErrorIs(t, err, stop)
	require.NoError(t, ctx.Err(), "message reader must stop promptly after callback failure")
}

func TestGitCommitMessageBatchFraming(t *testing.T) {
	// Large messages and embedded NUL bytes must not split batch records.
	message := "subject\n\n" + strings.Repeat("body\x00\n", 20000)
	object := "tree abc\nauthor Test <test@example.com> 0 +0000\n\n" + message
	batch := fmt.Sprintf("abc commit %d\n%s\n", len(object), object)
	reader := bufio.NewReader(strings.NewReader(batch + batch))
	for range 2 {
		f, err := readGitCommitMessage(reader)
		require.NoError(t, err)
		require.Equal(t, message, f.Raw)
	}
	for _, input := range []string{"abc missing\n", "abc blob 3\nfoo\n", "abc commit -1\n", "abc commit 5\nshort", "abc commit 2\n\n\nx", "abc commit 3\nabc\n"} {
		_, err := readGitCommitMessage(bufio.NewReader(strings.NewReader(input)))
		require.Error(t, err, input)
	}
}

func TestGitTagMessagesCoverage(t *testing.T) {
	repo := newGitTestRepo(t, 2)
	runGitTestCommand(t, repo, "config", "user.name", "Tagger")
	runGitTestCommand(t, repo, "config", "user.email", "tagger@example.com")
	message := "release subject\n\n  secret-tag\ndiff --git a/fake b/fake\ncommit fake\n\n"
	runGitTestCommand(t, repo, "tag", "-a", "release/v1", "--cleanup=verbatim", "-m", message)
	runGitTestCommand(t, repo, "tag", "release/v1-alias", "release/v1")
	runGitTestCommand(t, repo, "tag", "lightweight")
	runGitTestCommand(t, repo, "tag", "-a", "inner", "-m", "inner message")
	runGitTestCommand(t, repo, "tag", "-a", "outer", "-m", "outer message", "inner")
	runGitTestCommand(t, repo, "tag", "-d", "inner")
	runGitTestCommand(t, repo, "tag", "-a", "blob", "-m", "blob annotation", "HEAD:file-0.txt")
	runGitTestCommand(t, repo, "tag", "-a", "tree", "-m", "tree annotation", "HEAD^{tree}")

	for _, jobs := range []int{1, 2, 0} {
		for _, test := range []struct {
			name, logOpts                      string
			include                            []string
			wantTags, wantCommits, wantPatches int
		}{
			{name: "default", wantPatches: 2},
			{name: "tags", include: []string{GitResourceTypeTagMessages}, wantTags: 5, wantPatches: 2},
			{name: "both", include: []string{GitResourceTypeTagMessages, GitResourceTypeCommitMessages}, wantTags: 5, wantCommits: 2, wantPatches: 2},
			{name: "duplicate include", include: []string{GitResourceTypeTagMessages, GitResourceTypeTagMessages}, wantTags: 5, wantPatches: 2},
			{name: "empty commit selection", logOpts: "HEAD..HEAD", include: []string{GitResourceTypeTagMessages, GitResourceTypeCommitMessages}, wantTags: 5},
		} {
			t.Run(fmt.Sprintf("jobs=%d/%s", jobs, test.name), func(t *testing.T) {
				var mu sync.Mutex
				var fragments []Fragment
				source := &Git{RepoPath: repo, Jobs: jobs, Include: test.include, LogOpts: test.logOpts}
				require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
					mu.Lock()
					defer mu.Unlock()
					fragments = append(fragments, f)
					return err
				}))
				tags := make(map[string]string)
				commits, patches := 0, 0
				for _, f := range fragments {
					switch f.Attr(AttrResource) {
					case ResourceGitPatchContent:
						patches++
					case ResourceGitCommitMessage:
						commits++
					case ResourceGitTagMessage:
						require.NotContains(t, tags, f.Attr(AttrGitSHA), "aliases and nested refs must not duplicate annotations")
						tags[f.Attr(AttrGitSHA)] = f.Attr(AttrGitTagName)
						require.Equal(t, "Tagger", f.Attr(AttrGitTaggerName))
						require.Equal(t, "tagger@example.com", f.Attr(AttrGitTaggerEmail))
						require.NotEmpty(t, f.Attr(AttrGitDate))
						require.NotContains(t, f.Attributes, AttrGitAuthorName)
						require.NotContains(t, f.Attributes, AttrPath)
						require.Equal(t, 1, f.StartLine)
						require.Equal(t, f.Raw, f.Attr(AttrGitMessage))
						if f.Attr(AttrGitTagName) == "release/v1" {
							require.Equal(t, message, f.Raw)
							require.Equal(t, "refs/tags/release/v1", f.Attr(AttrGitTagRef))
						}
						if f.Attr(AttrGitTagName) == "inner" {
							require.Equal(t, "inner message\n", f.Raw)
							require.NotContains(t, f.Attributes, AttrGitTagRef)
						}
					default:
						t.Fatalf("unexpected resource %q", f.Attr(AttrResource))
					}
				}
				require.Len(t, tags, test.wantTags)
				require.Equal(t, test.wantCommits, commits)
				require.Equal(t, test.wantPatches, patches)
			})
		}
	}
}

func TestGitTagMessagesFilteringAndStop(t *testing.T) {
	repo := newGitTestRepo(t, 1)
	runGitTestCommand(t, repo, "tag", "-a", "first", "-m", "first message")
	runGitTestCommand(t, repo, "tag", "-a", "second", "-m", "second message")
	source := &Git{RepoPath: repo, Jobs: 1, Include: []string{GitResourceTypeTagMessages}}
	source.ShouldSkip = func(attrs map[string]string) bool { return attrs[AttrResource] == ResourceGitTagMessage }
	require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
		require.NotEqual(t, ResourceGitTagMessage, f.Attr(AttrResource))
		return err
	}))
	source.ShouldSkip = nil
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stop := errors.New("stop on tag")
	err := source.Fragments(ctx, func(f Fragment, err error) error {
		if f.Attr(AttrResource) == ResourceGitTagMessage {
			return stop
		}
		return err
	})
	require.ErrorIs(t, err, stop)
	require.NoError(t, ctx.Err(), "tag reader must stop promptly after callback failure")
	cancel()
	require.Error(t, source.Fragments(ctx, func(Fragment, error) error {
		t.Fatal("canceled scan yielded a fragment")
		return nil
	}))
}

func TestGitTagMessageBatchFraming(t *testing.T) {
	message := "subject\n\n" + strings.Repeat("body\x00\n", 20000) + "-----BEGIN PGP SIGNATURE-----\nsignature\n-----END PGP SIGNATURE-----\n"
	object := "object abc\ntype tag\ntag nested\ntagger Test <test@example.com> 981173106 +0230\n\n" + message
	batch := fmt.Sprintf("def tag %d\n%s\n", len(object), object)
	reader := bufio.NewReader(strings.NewReader(batch + batch))
	for range 2 {
		f, nested, err := readGitTagMessage(reader)
		require.NoError(t, err)
		require.Equal(t, message, f.Raw)
		require.Equal(t, "abc", nested)
		require.Equal(t, "def", f.Attr(AttrGitSHA))
		require.Equal(t, "2001-02-03T04:05:06Z", f.Attr(AttrGitDate))
	}
	for _, input := range []string{"abc missing\n", "abc commit 3\nfoo\n", "abc tag -1\n", "abc tag 5\nshort", "abc tag 2\n\n\nx", "abc tag 3\nabc\n"} {
		_, _, err := readGitTagMessage(bufio.NewReader(strings.NewReader(input)))
		require.Error(t, err, input)
	}
}

func TestGitTagMessagesWithoutAnnotations(t *testing.T) {
	for _, commits := range []int{0, 1} {
		repo := newGitTestRepo(t, commits)
		if commits > 0 {
			runGitTestCommand(t, repo, "tag", "lightweight")
		}
		for _, jobs := range []int{1, 2} {
			source := &Git{RepoPath: repo, Jobs: jobs, Include: []string{GitResourceTypeTagMessages}}
			require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
				require.NotEqual(t, ResourceGitTagMessage, f.Attr(AttrResource))
				return err
			}))
		}
	}
}

func TestGitReflogsCoverage(t *testing.T) {
	repo := newGitTestRepo(t, 1)
	base := runGitTestCommand(t, repo, "rev-parse", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "lost.txt"), []byte("secret-reset\n"), 0600))
	runGitTestCommand(t, repo, "add", ".")
	runGitTestCommand(t, repo, "commit", "-qm", "old subject\n\nsecret-body")
	original := runGitTestCommand(t, repo, "rev-parse", "HEAD")
	runGitTestCommand(t, repo, "commit", "--amend", "-qm", "amended subject")
	amended := runGitTestCommand(t, repo, "rev-parse", "HEAD")
	cmd := exec.Command("git", "-C", repo, "-c", "user.name=Reflog Actor", "-c", "user.email=actor@example.com", "reset", "--hard", base)
	cmd.Env = append(gitConfigIsolationEnv(), "GIT_REFLOG_ACTION=secret-reflog", "GIT_COMMITTER_DATE=2001-02-03T04:05:06+00:00")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)

	for _, jobs := range []int{1, 2, 0} {
		for _, test := range []struct {
			name, logOpts                         string
			include                               []string
			wantPatches, wantCommits, wantReflogs int
		}{
			{name: "default", wantPatches: 1},
			{name: "commit messages", include: []string{GitResourceTypeCommitMessages}, wantPatches: 1, wantCommits: 1},
			{name: "reflogs", include: []string{GitResourceTypeReflogs}, wantPatches: 3, wantReflogs: 8},
			{name: "both", include: []string{GitResourceTypeReflogs, GitResourceTypeCommitMessages}, wantPatches: 3, wantCommits: 3, wantReflogs: 8},
			{name: "duplicate include", include: []string{GitResourceTypeReflogs, GitResourceTypeReflogs}, wantPatches: 3, wantReflogs: 8},
			{name: "limited history", logOpts: "--all --max-count=1", include: []string{GitResourceTypeReflogs, GitResourceTypeCommitMessages}, wantPatches: 1, wantCommits: 1, wantReflogs: 8},
			{name: "empty history", logOpts: "--all --max-count=0", include: []string{GitResourceTypeReflogs, GitResourceTypeCommitMessages}, wantReflogs: 8},
			{name: "excluded history", logOpts: "--all ^" + original + " ^" + amended, include: []string{GitResourceTypeReflogs}, wantReflogs: 8},
		} {
			t.Run(fmt.Sprintf("jobs=%d/%s", jobs, test.name), func(t *testing.T) {
				var mu sync.Mutex
				var fragments []Fragment
				source := &Git{RepoPath: repo, Jobs: jobs, Include: test.include, LogOpts: test.logOpts}
				require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
					mu.Lock()
					defer mu.Unlock()
					fragments = append(fragments, f)
					return err
				}))
				patches, commits := make(map[string]bool), make(map[string]bool)
				reflogs, actions := 0, 0
				for _, f := range fragments {
					switch f.Attr(AttrResource) {
					case ResourceGitPatchContent:
						key := f.Attr(AttrGitSHA) + ":" + f.Attr(AttrPath)
						require.NotContains(t, patches, key, "history must deduplicate overlapping refs and reflogs")
						patches[key] = true
					case ResourceGitCommitMessage:
						require.NotContains(t, commits, f.Attr(AttrGitSHA))
						commits[f.Attr(AttrGitSHA)] = true
						if f.Attr(AttrGitSHA) == original {
							require.Contains(t, f.Raw, "secret-body")
						}
					case ResourceGitReflogMessage:
						reflogs++
						require.Equal(t, 1, f.StartLine)
						require.Equal(t, f.Raw, f.Attr(AttrGitMessage))
						require.NotEmpty(t, f.Attr(AttrGitReflogSelector))
						require.NotEmpty(t, f.Attr(AttrGitReflogRef))
						require.NotContains(t, f.Attributes, AttrGitAuthorName)
						require.NotContains(t, f.Attributes, AttrPath)
						if strings.Contains(f.Raw, "secret-reflog") {
							actions++
							require.Equal(t, base, f.Attr(AttrGitSHA))
							require.Equal(t, "Reflog Actor", f.Attr(AttrGitReflogActorName))
							require.Equal(t, "actor@example.com", f.Attr(AttrGitReflogActorEmail))
							require.Equal(t, "2001-02-03T04:05:06Z", f.Attr(AttrGitDate))
						}
					default:
						t.Fatalf("unexpected resource %q", f.Attr(AttrResource))
					}
				}
				require.Len(t, patches, test.wantPatches)
				require.Len(t, commits, test.wantCommits)
				require.Equal(t, test.wantReflogs, reflogs)
				if test.wantReflogs > 0 {
					require.Equal(t, 2, actions, "HEAD and the branch have separate reflog entries")
				}
				if test.wantPatches == 3 {
					require.Contains(t, patches, original+":lost.txt")
					require.Contains(t, patches, amended+":lost.txt")
				}
			})
		}
	}
}

func TestGitReflogsFilteringAndStop(t *testing.T) {
	repo := newGitTestRepo(t, 2)
	source := &Git{RepoPath: repo, Jobs: 1, Include: []string{GitResourceTypeReflogs}}
	source.ShouldSkip = func(attrs map[string]string) bool { return attrs[AttrResource] == ResourceGitReflogMessage }
	require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
		require.NotEqual(t, ResourceGitReflogMessage, f.Attr(AttrResource))
		return err
	}))
	source.ShouldSkip = nil
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stop := errors.New("stop on reflog")
	err := source.Fragments(ctx, func(f Fragment, err error) error {
		if f.Attr(AttrResource) == ResourceGitReflogMessage {
			return stop
		}
		return err
	})
	require.ErrorIs(t, err, stop)
	require.NoError(t, ctx.Err(), "reflog reader must stop promptly after callback failure")
	err = source.Fragments(ctx, func(f Fragment, err error) error {
		if f.Attr(AttrResource) == ResourceGitReflogMessage {
			cancel()
		}
		return err
	})
	require.ErrorIs(t, err, context.Canceled)
}

func TestGitReflogMessageFraming(t *testing.T) {
	message := "update: " + strings.Repeat("body\t", 20000) + "\nsecond line"
	record := "abc\x00HEAD@{981173106 +0230}\x00Actor\x00actor@example.com\x00" + message + "\x00"
	reader := bufio.NewReader(strings.NewReader(record + record))
	for range 2 {
		f, err := readGitReflogMessage(reader)
		require.NoError(t, err)
		require.Equal(t, message, f.Raw)
		require.Equal(t, "abc", f.Attr(AttrGitSHA))
		require.Equal(t, "HEAD", f.Attr(AttrGitReflogRef))
		require.Equal(t, "2001-02-03T04:05:06Z", f.Attr(AttrGitDate))
	}
	_, err := readGitReflogMessage(reader)
	require.ErrorIs(t, err, io.EOF)
	for _, input := range []string{"abc", "abc\x00", strings.TrimSuffix(record, "\x00"), "abc\x00HEAD@{bad}\x00Actor\x00email\x00message\x00", "abc\x00HEAD\x00Actor\x00email\x00message\x00"} {
		_, err := readGitReflogMessage(bufio.NewReader(strings.NewReader(input)))
		require.Error(t, err)
		require.NotErrorIs(t, err, io.EOF, "partial records must not be treated as a completed stream")
	}
}

func TestGitWithoutReflogs(t *testing.T) {
	for _, commits := range []int{0, 1} {
		repo := newGitTestRepo(t, commits)
		runGitTestCommand(t, repo, "reflog", "expire", "--expire=all", "--all")
		for _, jobs := range []int{1, 2} {
			patches := 0
			source := &Git{RepoPath: repo, Jobs: jobs, Include: []string{GitResourceTypeReflogs}}
			require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
				require.Equal(t, ResourceGitPatchContent, f.Attr(AttrResource))
				patches++
				return err
			}))
			require.Equal(t, commits, patches)
		}
	}
}

func TestGitSourcesShareInheritedJobBudget(t *testing.T) {
	for _, command := range []bool{false, true} {
		t.Run(fmt.Sprintf("command=%t", command), func(t *testing.T) {
			repo := newGitTestRepo(t, 4)
			ctx := sourcejobs.WithBudget(t.Context(), sourcejobs.NewBudget(1))
			started := make(chan struct{}, 32)
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseAll()
			done := make(chan error, 2)
			gitSources := []*Git{{RepoPath: repo, Jobs: 4}, {RepoPath: repo, Jobs: 4}}
			for _, source := range gitSources {
				if command {
					cmd, err := NewGitLogCmdContext(ctx, repo, "")
					require.NoError(t, err)
					source.Cmd = cmd
				}
			}
			for _, source := range gitSources {
				go func() {
					done <- source.Fragments(ctx, func(_ Fragment, err error) error {
						if err != nil {
							return err
						}
						started <- struct{}{}
						<-release
						return nil
					})
				}()
			}
			select {
			case <-started:
			case err := <-done:
				require.NoError(t, err)
				t.Fatal("Git scan completed before yielding a fragment")
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for budgeted Git work")
			}
			select {
			case <-started:
				t.Fatal("nested Git scans exceeded their shared job budget")
			case <-time.After(100 * time.Millisecond):
			}
			releaseAll()
			for range gitSources {
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Fatal("timed out completing budgeted Git scans")
				}
			}
			for _, source := range gitSources {
				require.Equal(t, Git{RepoPath: repo, Jobs: 4, Cmd: source.Cmd}, *source, "scan must not mutate source configuration")
			}
		})
	}
}
