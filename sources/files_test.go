package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilesDoesNotRepeatPrefilterForAcceptedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.txt")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("content\n\n", 100_000)), 0o600))
	var checks, fragments atomic.Int32
	source := &Files{Path: path, ShouldSkip: func(map[string]string) bool {
		checks.Add(1)
		return false
	}}
	require.NoError(t, source.Fragments(t.Context(), func(_ Fragment, err error) error {
		fragments.Add(1)
		return err
	}))
	require.Greater(t, fragments.Load(), int32(1))
	wantChecks := int32(1)
	if isWindows {
		wantChecks = 2 // Native and forward-slash paths are both checked.
	}
	require.Equal(t, wantChecks, checks.Load())
}

func TestFilesFragmentsOwnContents(t *testing.T) {
	root := t.TempDir()
	contents := make(map[string]string)
	for i := range 6 {
		path := filepath.Join(root, fmt.Sprintf("%d.txt", i))
		contents[path] = strings.Repeat(fmt.Sprintf("file %d\n", i), 1000)
		require.NoError(t, os.WriteFile(path, []byte(contents[path]), 0o600))
	}
	// One reader forces buffer reuse before retained fragments are inspected.
	source := &Files{Path: root, Workers: 1}
	var fragments []Fragment
	require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
		fragments = append(fragments, fragment)
		return err
	}))
	require.Len(t, fragments, len(contents))
	for _, fragment := range fragments {
		require.Equal(t, contents[filepath.FromSlash(fragment.Attr(AttrPath))], fragment.Raw)
		require.Equal(t, 1, fragment.StartLine)
	}
}

func TestFilesConcurrencyAndCancellation(t *testing.T) {
	root := t.TempDir()
	for i := range 32 {
		require.NoError(t, os.WriteFile(filepath.Join(root, fmt.Sprintf("%d.txt", i)), []byte("content"), 0o600))
	}
	for _, test := range []struct {
		name    string
		cpus    int
		workers int
		want    int
	}{
		{name: "automatic single CPU", cpus: 1, want: 1},
		{name: "automatic two CPUs", cpus: 2, want: 2},
		{name: "automatic ten CPUs", cpus: 10, want: 10},
		{name: "explicit workers exceed CPUs", cpus: 2, workers: 3, want: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := runtime.GOMAXPROCS(test.cpus)
			t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
			for _, cancelScan := range []bool{false, true} {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				source := &Files{Path: root, Workers: test.workers}
				started := make(chan struct{}, 32)
				release := make(chan struct{})
				done := make(chan error, 1)
				callbackErr := errors.New("stop callback")
				go func() {
					done <- source.Fragments(ctx, func(_ Fragment, err error) error {
						if err != nil {
							return err
						}
						started <- struct{}{}
						select {
						case <-release:
							return callbackErr
						case <-ctx.Done():
							return nil
						}
					})
				}()
				for range test.want {
					select {
					case <-started:
					case <-ctx.Done():
						t.Fatal("workers failed to start")
					}
				}
				select {
				case <-started:
					t.Fatal("exceeded the file worker limit")
				case <-time.After(20 * time.Millisecond):
				}
				want := callbackErr
				if cancelScan {
					want = context.Canceled
					cancel()
				} else {
					close(release)
				}
				select {
				case err := <-done:
					require.ErrorIs(t, err, want)
				case <-time.After(5 * time.Second):
					t.Fatal("source did not join its workers")
				}
				cancel()
			}
		})
	}
}

func TestFilesMissingRootReturnsError(t *testing.T) {
	source := &Files{Path: filepath.Join(t.TempDir(), "missing"), Workers: 1}
	yield := func(Fragment, error) error {
		t.Error("missing root should fail before yielding")
		return nil
	}
	require.ErrorIs(t, source.Fragments(t.Context(), yield), fs.ErrNotExist)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, source.Fragments(ctx, yield), context.Canceled)
}

func TestFilesPrefilterPrecedesSizeChecks(t *testing.T) {
	for _, size := range []int{0, 100} {
		path := filepath.Join(t.TempDir(), "skip.txt")
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), size), 0o600))
		var output bytes.Buffer
		checks := 0
		source := &Files{
			Path:        path,
			MaxFileSize: 10,
			Logger:      slog.New(slog.NewJSONHandler(&output, nil)),
			ShouldSkip: func(attrs map[string]string) bool {
				require.Equal(t, path, attrs[AttrPath])
				checks++
				return true
			},
		}
		require.NoError(t, source.walkFiles(t.Context(), func(filePath) error {
			t.Error("prefiltered file must not be scanned")
			return nil
		}))
		require.Equal(t, 1, checks)
		require.Empty(t, output.String(), "rejected paths should not produce size warnings")
	}
}

func TestFilesDirectoryPrefilterPrunesTraversal(t *testing.T) {
	root := t.TempDir()
	skipped := filepath.Join(root, "skip")
	require.NoError(t, os.Mkdir(skipped, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(skipped, "ignored.txt"), []byte("ignored"), 0o600))
	accepted := filepath.Join(root, "keep.txt")
	require.NoError(t, os.WriteFile(accepted, []byte("keep"), 0o600))
	for _, follow := range []bool{false, true} {
		source := &Files{Path: root, FollowSymlinks: follow, ShouldSkip: func(attrs map[string]string) bool {
			path := filepath.FromSlash(attrs[AttrPath])
			if strings.HasPrefix(path, skipped+string(filepath.Separator)) {
				t.Errorf("visited child of skipped directory: %s", path)
			}
			return path == skipped
		}}
		var targets []string
		require.NoError(t, source.walkFiles(t.Context(), func(name filePath) error {
			targets = append(targets, name.path)
			return nil
		}))
		require.Equal(t, []string{accepted}, targets)
	}
}

func TestFilesPrefilterStillAppliesToArchiveEntries(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range []string{"keep.txt", "skip.txt"} {
		entry, err := writer.Create(name)
		require.NoError(t, err)
		_, err = io.WriteString(entry, "content\n")
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	path := filepath.Join(t.TempDir(), "bundle.zip")
	require.NoError(t, os.WriteFile(path, archive.Bytes(), 0o600))
	source := &Files{Path: path, MaxArchiveDepth: 1, ShouldSkip: func(attrs map[string]string) bool {
		return strings.HasSuffix(attrs[AttrPath], "!skip.txt")
	}}
	var paths []string
	require.NoError(t, source.Fragments(t.Context(), func(fragment Fragment, err error) error {
		paths = append(paths, fragment.Attr(AttrPath))
		return err
	}))
	require.Equal(t, []string{filepath.ToSlash(path) + "!keep.txt"}, paths)
}

func TestFilesWalkFilesPathsMatchFilepathWalkDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.txt"), []byte("one"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "two.txt"), []byte("two"), 0o600))

	// A "." root is the default for `betterleaks fs`. Use the equivalent
	// absolute spelling so this test does not need to change the process-wide
	// working directory.
	scanRoot := root + string(filepath.Separator) + "."

	var wantVisited, wantTargets []string
	require.NoError(t, filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		wantVisited = append(wantVisited, path)
		if !d.IsDir() {
			wantTargets = append(wantTargets, path)
		}
		return nil
	}))

	// shouldSkipPath evaluates both the native and forward-slash forms on
	// Windows for compatibility with path filters.
	if isWindows {
		nativePaths := append([]string(nil), wantVisited...)
		for _, path := range nativePaths {
			wantVisited = append(wantVisited, filepath.ToSlash(path))
		}
	}

	var (
		visitedMu sync.Mutex
		visited   []string
		targets   []string
	)
	source := &Files{
		Path: scanRoot,
		ShouldSkip: func(attrs map[string]string) bool {
			visitedMu.Lock()
			visited = append(visited, attrs[AttrPath])
			visitedMu.Unlock()
			return false
		},
	}
	require.NoError(t, source.walkFiles(t.Context(), func(name filePath) error {
		targets = append(targets, name.path)
		return nil
	}))

	sort.Strings(wantVisited)
	sort.Strings(wantTargets)
	sort.Strings(visited)
	sort.Strings(targets)
	require.Equal(t, wantVisited, visited)
	require.Equal(t, wantTargets, targets)
}

func TestFilesJobsLimitConcurrency(t *testing.T) {
	const fileCount = 6

	root := t.TempDir()
	for i := range fileCount {
		path := filepath.Join(root, fmt.Sprintf("%d.txt", i))
		require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))
	}

	source := &Files{Path: root, Workers: 2}
	started := make(chan struct{}, fileCount)
	release := make(chan struct{})
	done := make(chan error, 1)
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()

	var active atomic.Int64
	var peak atomic.Int64
	var yielded atomic.Int64
	go func() {
		done <- source.Fragments(t.Context(), func(_ Fragment, err error) error {
			if err != nil {
				return err
			}
			current := active.Add(1)
			for {
				previous := peak.Load()
				if current <= previous || peak.CompareAndSwap(previous, current) {
					break
				}
			}
			yielded.Add(1)
			started <- struct{}{}
			<-release
			active.Add(-1)
			return nil
		})
	}()

	for range source.Workers {
		select {
		case <-started:
		case err := <-done:
			require.NoError(t, err)
			t.Fatal("scan completed before filling the worker pool")
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for workers")
		}
	}

	select {
	case <-started:
		t.Fatal("source exceeded its worker limit")
	case <-time.After(50 * time.Millisecond):
	}

	releaseAll()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for scan completion")
	}

	require.Equal(t, int64(source.Workers), peak.Load())
	require.Equal(t, int64(fileCount), yielded.Load())
}

func TestFilesFollowDirectorySymlinks(t *testing.T) {
	disk := t.TempDir()
	volumes := filepath.Join(disk, "Volumes")
	require.NoError(t, os.Mkdir(volumes, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(disk, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(disk, "one.txt"), []byte("one"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(disk, "nested", "two.txt"), []byte("two"), 0o600))
	link := filepath.Join(volumes, "Macintosh HD")
	require.NoError(t, os.Symlink(disk, link))
	require.NoError(t, os.Symlink(disk, filepath.Join(volumes, "alias")))
	require.NoError(t, os.Symlink("..", filepath.Join(disk, "nested", "back")))
	for _, root := range []string{volumes, link} {
		for _, follow := range []bool{false, true} {
			source := &Files{Path: root, FollowSymlinks: follow, Workers: 1}
			for range 2 { // Directory deduplication must be scoped to each scan.
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				var contents []string
				err := source.Fragments(ctx, func(f Fragment, err error) error {
					if err != nil {
						return err
					}
					contents = append(contents, f.Raw)
					return nil
				})
				cancel()
				require.NoError(t, err)
				if follow {
					require.ElementsMatch(t, []string{"one", "two"}, contents)
				} else {
					require.Empty(t, contents)
				}
			}
		}
	}
}

func TestFilesDirectorySymlinkPrefilter(t *testing.T) {
	root, target := t.TempDir(), t.TempDir()
	// Resolve macOS's temporary-directory prefix so target matches EvalSymlinks.
	target, err := filepath.EvalSymlinks(target)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(target, "secret.txt"), []byte("secret"), 0o600))
	link := filepath.Join(root, "linked")
	require.NoError(t, os.Symlink(target, link))
	for _, scanRoot := range []string{root, link} {
		for _, skipped := range []string{link, target} {
			source := &Files{Path: scanRoot, FollowSymlinks: true, ShouldSkip: func(attrs map[string]string) bool {
				return attrs[AttrPath] == skipped
			}}
			require.NoError(t, source.walkFiles(t.Context(), func(filePath) error {
				t.Error("prefiltered directory must not be scanned")
				return nil
			}))
		}
	}
}

func TestFilesSymlinksUseTargetSizeAndHandleBrokenLinks(t *testing.T) {
	root, target := t.TempDir(), t.TempDir()
	target, err := filepath.EvalSymlinks(target)
	require.NoError(t, err)
	for _, file := range []struct{ name, content string }{
		{"small", "ok"}, {"large", strings.Repeat("x", 1024)}, {"empty", ""},
	} {
		require.NoError(t, os.WriteFile(filepath.Join(target, file.name), []byte(file.content), 0o600))
		require.NoError(t, os.Symlink(filepath.Join(target, file.name), filepath.Join(root, file.name)))
	}
	require.NoError(t, os.Symlink("missing", filepath.Join(root, "broken")))
	require.NoError(t, os.Symlink("loop", filepath.Join(root, "loop")))
	source := &Files{Path: root, FollowSymlinks: true, MaxFileSize: 10}
	var paths []filePath
	require.NoError(t, source.walkFiles(t.Context(), func(name filePath) error {
		paths = append(paths, name)
		return nil
	}))
	require.Equal(t, []filePath{{path: filepath.Join(target, "small"), symlink: filepath.Join(root, "small")}}, paths)
}

func TestFilesUnreadableDirectoriesDoNotAbortScan(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, "denied")
	require.NoError(t, os.Mkdir(denied, 0o700))
	require.NoError(t, os.Chmod(denied, 0))
	t.Cleanup(func() { _ = os.Chmod(denied, 0o700) })
	if _, err := os.ReadDir(denied); !os.IsPermission(err) {
		t.Skip("requires filesystem permission enforcement")
	}
	link := filepath.Join(root, "denied-link")
	require.NoError(t, os.Symlink(denied, link))
	for _, name := range []string{"one", "two", "three"} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "readable.txt"), []byte(name), 0o600))
	}
	for _, follow := range []bool{false, true} {
		for _, path := range []string{root, denied, link} {
			source := &Files{Path: path, FollowSymlinks: follow, Workers: 1}
			var contents []string
			err := source.Fragments(t.Context(), func(f Fragment, err error) error {
				if err != nil {
					return err
				}
				contents = append(contents, f.Raw)
				return nil
			})
			require.NoError(t, err, "root=%s follow=%t", path, follow)
			if path == root {
				require.ElementsMatch(t, []string{"one", "two", "three"}, contents)
			} else {
				require.Empty(t, contents)
			}
		}
	}
}

func TestFilesDisappearingDirectoryDoesNotAbortScan(t *testing.T) {
	for _, follow := range []bool{false, true} {
		root := t.TempDir()
		vanishing := filepath.Join(root, "vanishing")
		require.NoError(t, os.Mkdir(vanishing, 0o700))
		readable := filepath.Join(root, "readable.txt")
		require.NoError(t, os.WriteFile(readable, []byte("readable"), 0o600))
		source := &Files{Path: root, FollowSymlinks: follow, ShouldSkip: func(attrs map[string]string) bool {
			if attrs[AttrPath] == vanishing {
				// Remove it after inspection but before fastwalk reads it.
				if err := os.Remove(vanishing); err != nil {
					t.Errorf("remove directory: %v", err)
				}
			}
			return false
		}}
		var paths []string
		require.NoError(t, source.walkFiles(t.Context(), func(name filePath) error {
			paths = append(paths, name.path)
			return nil
		}))
		require.Equal(t, []string{readable}, paths)
	}
}

func TestFilesWalkFilesPreservesCancellationAndCallbackErrors(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "readable.txt"), []byte("readable"), 0o600))
	for _, follow := range []bool{false, true} {
		source := &Files{Path: root, FollowSymlinks: follow}
		callbackErr := errors.New("callback failed")
		err := source.walkFiles(t.Context(), func(filePath) error { return callbackErr })
		require.ErrorIs(t, err, callbackErr)
		ctx, cancel := context.WithCancel(t.Context())
		err = source.walkFiles(ctx, func(filePath) error {
			cancel()
			return ctx.Err()
		})
		cancel()
		require.ErrorIs(t, err, context.Canceled)
	}
}

type testLogRecord struct {
	Message string `json:"msg"`
	Path    string `json:"path"`
}

func TestSourceLoggingIsOptIn(t *testing.T) {
	assert.Equal(t, slog.DiscardHandler, logging.OrDiscard(nil).Handler())

	var output bytes.Buffer
	source := &Files{
		Logger:      slog.New(slog.NewJSONHandler(&output, nil)),
		Path:        filepath.Join(t.TempDir(), "large.txt"),
		MaxFileSize: 1,
	}

	require.NoError(t, os.WriteFile(source.Path, []byte("large"), 0o600))
	err := source.Fragments(t.Context(), func(Fragment, error) error { return nil })
	require.NoError(t, err)
	record := decodeLogRecord(t, output.Bytes())
	assert.Equal(t, "skipping file: too large", record.Message)
	assert.Equal(t, source.Path, record.Path)
}

func TestSourceLoggersAreIndependent(t *testing.T) {
	var firstOutput, secondOutput bytes.Buffer
	first := &Files{
		Logger:      slog.New(slog.NewJSONHandler(&firstOutput, nil)),
		Path:        filepath.Join(t.TempDir(), "first.txt"),
		MaxFileSize: 1,
	}
	second := &Files{
		Logger:      slog.New(slog.NewJSONHandler(&secondOutput, nil)),
		Path:        filepath.Join(t.TempDir(), "second.txt"),
		MaxFileSize: 1,
	}

	require.NoError(t, os.WriteFile(first.Path, []byte("large"), 0o600))
	require.NoError(t, os.WriteFile(second.Path, []byte("large"), 0o600))
	yield := func(Fragment, error) error { return nil }
	require.NoError(t, first.Fragments(t.Context(), yield))
	require.NoError(t, second.Fragments(t.Context(), yield))

	firstRecord := decodeLogRecord(t, firstOutput.Bytes())
	secondRecord := decodeLogRecord(t, secondOutput.Bytes())
	assert.Equal(t, first.Path, firstRecord.Path)
	assert.NotEqual(t, second.Path, firstRecord.Path)
	assert.Equal(t, second.Path, secondRecord.Path)
	assert.NotEqual(t, first.Path, secondRecord.Path)
}

func decodeLogRecord(t *testing.T, data []byte) testLogRecord {
	t.Helper()
	var record testLogRecord
	require.NoError(t, json.Unmarshal(data, &record))
	return record
}
