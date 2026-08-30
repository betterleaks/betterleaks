package sources

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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
