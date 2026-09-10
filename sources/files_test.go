package sources

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFilesScanTargetsPathsMatchFilepathWalkDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.txt"), []byte("one"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "nested", "two.txt"), []byte("two"), 0o600))

	// A "." root is the default for `betterleaks dir`. Use the equivalent
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
	require.NoError(t, source.scanTargets(t.Context(), func(target ScanTarget, err error) error {
		if err != nil {
			return err
		}
		targets = append(targets, target.Path)
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

	source := &Files{Path: root, Jobs: 2}
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

	for range source.Jobs {
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

	require.Equal(t, int64(source.Jobs), peak.Load())
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
			source := &Files{Path: root, FollowSymlinks: follow, Jobs: 1}
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
			require.NoError(t, source.scanTargets(t.Context(), func(ScanTarget, error) error {
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
	var targets []ScanTarget
	require.NoError(t, source.scanTargets(t.Context(), func(target ScanTarget, err error) error {
		targets = append(targets, target)
		return err
	}))
	require.Equal(t, []ScanTarget{{Path: filepath.Join(target, "small"), Symlink: filepath.Join(root, "small")}}, targets)
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
			source := &Files{Path: path, FollowSymlinks: follow, Jobs: 1}
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
		require.NoError(t, source.scanTargets(t.Context(), func(target ScanTarget, err error) error {
			paths = append(paths, target.Path)
			return err
		}))
		require.Equal(t, []string{readable}, paths)
	}
}

func TestFilesScanTargetsPreservesCancellationAndCallbackErrors(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "readable.txt"), []byte("readable"), 0o600))
	for _, follow := range []bool{false, true} {
		source := &Files{Path: root, FollowSymlinks: follow}
		callbackErr := errors.New("callback failed")
		err := source.scanTargets(t.Context(), func(ScanTarget, error) error { return callbackErr })
		require.ErrorIs(t, err, callbackErr)
		ctx, cancel := context.WithCancel(t.Context())
		err = source.scanTargets(ctx, func(ScanTarget, error) error {
			cancel()
			return ctx.Err()
		})
		cancel()
		require.ErrorIs(t, err, context.Canceled)
	}
}
