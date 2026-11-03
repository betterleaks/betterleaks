package sources

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitMetadataCopyLimits(t *testing.T) {
	t.Run("aggregate across source directories", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		c.remainingBytes = 8
		for i := range 2 {
			src := filepath.Join(t.TempDir(), "source")
			dst := filepath.Join(t.TempDir(), "target")
			require.NoError(t, os.WriteFile(src, []byte("12345"), 0o600))
			err := c.copyFile(t.Context(), src, dst)
			if i == 0 {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "byte limit")
				require.NoFileExists(t, dst)
			}
		}
	})
	t.Run("per file", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		c.maxFileBytes = 4
		src := filepath.Join(t.TempDir(), "source")
		dst := filepath.Join(t.TempDir(), "target")
		require.NoError(t, os.WriteFile(src, []byte("12345"), 0o600))
		require.ErrorContains(t, c.copyFile(t.Context(), src, dst), "byte limit")
		require.NoFileExists(t, dst)
	})
	t.Run("stream exceeds observed size", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		c.remainingBytes = 5
		var out bytes.Buffer
		err := c.copyContents(t.Context(), strings.NewReader("123456"), &out, 5)
		require.ErrorContains(t, err, "byte limit")
		require.Equal(t, "12345", out.String())
		require.Zero(t, c.remainingBytes)
	})
	t.Run("exact stream limit", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		c.remainingBytes = 5
		var out bytes.Buffer
		require.NoError(t, c.copyContents(t.Context(), strings.NewReader("12345"), &out, 5))
		require.Equal(t, "12345", out.String())
		require.Zero(t, c.remainingBytes)
	})
	t.Run("entries include ignored files and empty directories", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		c.remainingEntries = 4
		src := t.TempDir()
		for i := range 3 {
			require.NoError(t, os.WriteFile(filepath.Join(src, fmt.Sprintf("%d.lock", i)), nil, 0o600))
			require.NoError(t, os.Mkdir(filepath.Join(src, fmt.Sprintf("dir%d", i)), 0o700))
		}
		root, err := c.root(src)
		require.NoError(t, err)
		require.ErrorContains(t, c.copyTree(t.Context(), root, ".", t.TempDir(), 0), "entry limit")
	})
	t.Run("depth", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		c.maxDepth = 2
		src := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(src, "a", "b", "c"), 0o700))
		root, err := c.root(src)
		require.NoError(t, err)
		require.ErrorContains(t, c.copyTree(t.Context(), root, ".", t.TempDir(), 0), "depth limit")
	})
	t.Run("canceled", func(t *testing.T) {
		c := newGitMetadataCopier()
		defer c.Close()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, c.copyFile(ctx, "unused", "unused"), context.Canceled)
	})
}

func TestReadGitFileLimit(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(file, []byte("[core]\n"), 0o600))
	require.NoError(t, os.Truncate(file, gitMetadataReadLimit+1))
	_, err := readGitFile(file)
	require.ErrorContains(t, err, "read limit")
	_, err = readGitConfig(t.Context(), file)
	require.ErrorContains(t, err, "read limit")
}

func TestGitMetadataPinnedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming open directories and creating symlinks requires platform-specific privileges")
	}
	src := filepath.Join(t.TempDir(), "source")
	require.NoError(t, os.Mkdir(src, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(src, "ref"), []byte("original"), 0o600))
	c := newGitMetadataCopier()
	defer c.Close()
	_, err := c.root(src)
	require.NoError(t, err)
	require.NoError(t, os.Rename(src, src+"-moved"))
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "ref"), []byte("outside"), 0o600))
	require.NoError(t, os.Symlink(outside, src))
	dst := filepath.Join(t.TempDir(), "ref")
	require.NoError(t, c.copyFile(t.Context(), filepath.Join(src, "ref"), dst))
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	require.Equal(t, "original", string(got))
}

func TestGitMetadataRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require privileges on Windows")
	}
	src := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "ref"), []byte("outside"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(src, "refs")))
	require.NoError(t, os.Symlink(filepath.Join(outside, "ref"), filepath.Join(src, "HEAD")))
	c := newGitMetadataCopier()
	defer c.Close()
	root, err := c.root(src)
	require.NoError(t, err)
	dst := t.TempDir()
	require.Error(t, c.copyTree(t.Context(), root, "refs", dst, 0))
	require.Error(t, c.copyFile(t.Context(), filepath.Join(src, "refs", "ref"), filepath.Join(dst, "ref")))
	require.Error(t, c.copyFile(t.Context(), filepath.Join(src, "HEAD"), filepath.Join(dst, "HEAD")))
	_, err = readGitFile(filepath.Join(src, "HEAD"))
	require.Error(t, err)
}

func TestGitMetadataConcurrentFileReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require privileges on Windows")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0o600))
	file := filepath.Join(dir, "ref")
	require.NoError(t, os.WriteFile(file, []byte("original"), 0o600))
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer root.Close()
	check := func() {
		f, err := openGitMetadata(root, "ref", false)
		if err != nil {
			return // Concurrent changes may fail closed.
		}
		data, err := io.ReadAll(f)
		closeErr := f.Close()
		require.NoError(t, err)
		require.NoError(t, closeErr)
		require.Equal(t, "original", string(data))
	}
	check()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			tmp := filepath.Join(dir, "replacement")
			if err := os.Symlink(outside, tmp); err != nil {
				done <- err
				return
			}
			if err := os.Rename(tmp, file); err != nil {
				done <- err
				return
			}
			if err := os.WriteFile(tmp, []byte("original"), 0o600); err != nil {
				done <- err
				return
			}
			if err := os.Rename(tmp, file); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	defer func() {
		cancel()
		require.NoError(t, <-done)
	}()
	for range 200 {
		check()
	}
}
