package sources

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilesWorkerPoolFragments(t *testing.T) {
	root := t.TempDir()
	want := make(map[string]string)
	for _, name := range []string{"one.txt", "two.txt", "three.txt", "four.txt"} {
		content := "content for " + name
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		want[path] = content
	}

	got := make(map[string]string)
	var gotMu sync.Mutex
	source := &Files{Path: root, Workers: 2}
	err := source.Fragments(t.Context(), func(fragment *Fragment, err error) error {
		defer fragment.Release()
		if err != nil {
			return err
		}
		gotMu.Lock()
		got[fragment.Attr(AttrPath)] = string(fragment.Raw)
		gotMu.Unlock()
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestFilesWorkerPoolReturnsYieldErrors(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.txt"), []byte("one"), 0o600))
	wantErr := errors.New("stop this file")
	source := &Files{Path: root, Workers: 2}
	err := source.Fragments(t.Context(), func(fragment *Fragment, _ error) error {
		fragment.Release()
		return wantErr
	})
	require.ErrorIs(t, err, wantErr)
}

func TestFilesScanTargetsPrefersPathSkipFunc(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "one.txt"), []byte("one"), 0o600))

	var pathCalls, fallbackCalls atomic.Int64
	source := &Files{
		Path: root,
		ShouldSkipPath: func(string) bool {
			pathCalls.Add(1)
			return false
		},
		ShouldSkip: func(map[string]string) bool {
			fallbackCalls.Add(1)
			return false
		},
	}
	require.NoError(t, source.scanTargets(t.Context(), func(ScanTarget, error) error { return nil }))
	require.Positive(t, pathCalls.Load())
	require.Zero(t, fallbackCalls.Load())
}

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
