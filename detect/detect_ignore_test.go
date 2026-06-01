package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddGitleaksIgnore_pathGlobs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ignorePath := filepath.Join(dir, ".betterleaksignore")
	content := `# fixtures
fixtures/test-keys/**
api/api.go:aws-access-key:7
`
	require.NoError(t, os.WriteFile(ignorePath, []byte(content), 0o600))

	d := NewDetector(nil)
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))

	require.Equal(t, []string{"fixtures/test-keys/**"}, d.PathExcludeGlobs())
	_, ok := d.gitleaksIgnore["api/api.go:aws-access-key:7"]
	require.True(t, ok)
}
