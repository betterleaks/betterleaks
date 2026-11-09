package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckReportPathWritableKeepsDevice(t *testing.T) {
	require.NoError(t, checkReportPathWritable(os.DevNull))

	info, err := os.Stat(os.DevNull)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeDevice)
}

func TestCheckReportPathWritableKeepsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	require.NoError(t, os.WriteFile(target, []byte("kept"), 0o644))
	link := filepath.Join(dir, "link.json")
	require.NoError(t, os.Symlink(target, link))

	require.NoError(t, checkReportPathWritable(link))

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, info.Mode().Type())
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "kept", string(content))
}

func TestCheckReportPathWritableAcceptsSymlinkToNewFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require privileges on Windows")
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "link.json")
	require.NoError(t, os.Symlink("target.json", link))

	require.NoError(t, checkReportPathWritable(link))

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, info.Mode().Type())
	_, err = os.Lstat(filepath.Join(dir, "target.json"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestCheckReportPathWritableLeavesNoNewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")

	require.NoError(t, checkReportPathWritable(path))

	_, err := os.Lstat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestCheckReportPathWritableRejectsMissingDirectory(t *testing.T) {
	assert.Error(t, checkReportPathWritable(filepath.Join(t.TempDir(), "missing", "report.json")))
}
