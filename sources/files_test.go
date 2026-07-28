package sources

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

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
