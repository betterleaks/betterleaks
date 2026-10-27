package gitfs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadOnlyFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "data"), []byte("0123456789"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "empty"), nil, 0600))
	for _, opts := range [][]Option{
		nil,
		{WithMmap()},
		{WithFilePool(NewFilePool(t.Context(), 1))},
		{WithMmap(), WithFilePool(NewFilePool(t.Context(), 1))},
	} {
		fs := New(root, opts...)
		f, err := fs.Open("data")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, f.Close()) })
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for off := range int64(10) {
					var b [1]byte
					n, err := f.ReadAt(b[:], off)
					assert.NoError(t, err)
					assert.Equal(t, 1, n)
					assert.Equal(t, byte('0'+off), b[0])
				}
			})
		}
		wg.Wait()
		_, err = f.Seek(3, io.SeekStart)
		require.NoError(t, err)
		data, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, "3456789", string(data))
		_, err = f.Write([]byte("x"))
		require.ErrorIs(t, err, os.ErrPermission)
		require.NoError(t, f.Close())
		_, err = f.ReadAt(make([]byte, 1), 0)
		require.Error(t, err, "closed mappings must not access unmapped memory")
		empty, err := fs.Open("empty")
		require.NoError(t, err)
		data, err = io.ReadAll(empty)
		require.NoError(t, err)
		require.Empty(t, data)
		require.NoError(t, empty.Close())
		_, err = fs.OpenFile("data", os.O_RDWR, 0600)
		require.ErrorIs(t, err, os.ErrPermission)
	}
}

func TestFilePoolEviction(t *testing.T) {
	pool := NewFilePool(t.Context(), 3)
	var files []billy.File
	for directory := range 2 {
		root := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(root, "child"), 0700))
		fs, err := New(root, WithFilePool(pool)).Chroot("child")
		require.NoError(t, err)
		for n := range 12 {
			name := fmt.Sprintf("%d-%d", directory, n)
			require.NoError(t, os.WriteFile(filepath.Join(root, "child", name), []byte(name), 0600))
			f, err := fs.Open(name)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })
			files = append(files, f)
			_, err = f.Seek(1, io.SeekStart)
			require.NoError(t, err)
		}
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for n := range 100 {
				f := files[(n+worker)%len(files)]
				want := filepath.Base(f.Name())
				b := make([]byte, len(want))
				_, err := f.ReadAt(b, 0)
				assert.NoError(t, err)
				assert.Equal(t, want, string(b))
				pool.mu.Lock()
				assert.LessOrEqual(t, len(pool.files), 3, "reads across roots must share the descriptor bound")
				pool.mu.Unlock()
			}
		})
	}
	wg.Wait()
	for _, f := range files {
		b, err := io.ReadAll(f)
		require.NoError(t, err)
		require.Equal(t, filepath.Base(f.Name())[1:], string(b), "ReadAt and eviction must preserve the cursor")
		require.NoError(t, f.Close())
		require.NoError(t, f.Close())
		_, err = f.Seek(0, io.SeekStart)
		require.ErrorIs(t, err, os.ErrClosed)
		_, err = f.ReadAt(make([]byte, 1), 0)
		require.ErrorIs(t, err, os.ErrClosed)
	}
	require.Empty(t, pool.files, "closing every logical file must release all descriptors")
}

func TestFilePoolBusyCancellation(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "data"), []byte("data"), 0600))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pool := NewFilePool(ctx, 1)
	fs := New(root, WithFilePool(pool))
	f, err := fs.Open("data")
	require.NoError(t, err)
	defer f.Close()
	pinned := f.(*pooledFile)
	handle, err := pinned.acquire()
	require.NoError(t, err)
	defer pinned.release()
	done := make(chan error, 1)
	go func() {
		other, err := fs.Open("data")
		if other != nil {
			other.Close()
		}
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("waiting for a descriptor ignored cancellation")
	}
	b := make([]byte, 4)
	_, err = handle.ReadAt(b, 0)
	require.NoError(t, err, "an active descriptor must not be evicted")
	require.Equal(t, "data", string(b))
}

func TestFilePoolReopenValidation(t *testing.T) {
	for _, change := range []string{"replace", "truncate", "escape"} {
		t.Run(change, func(t *testing.T) {
			if change == "escape" && runtime.GOOS == "windows" {
				t.Skip("symlink creation can require privileges on Windows")
			}
			parent := t.TempDir()
			root := filepath.Join(parent, "root")
			require.NoError(t, os.Mkdir(root, 0700))
			name := filepath.Join(root, "data")
			require.NoError(t, os.WriteFile(name, []byte("old"), 0600))
			require.NoError(t, os.WriteFile(filepath.Join(root, "other"), []byte("other"), 0600))
			fs := New(root, WithFilePool(NewFilePool(t.Context(), 1)))
			f, err := fs.Open("data")
			require.NoError(t, err)
			defer f.Close()
			other, err := fs.Open("other") // Evict data before changing its path.
			require.NoError(t, err)
			defer other.Close()
			switch change {
			case "replace":
				require.NoError(t, os.Rename(name, name+".old"))
				require.NoError(t, os.WriteFile(name, []byte("new"), 0600))
			case "truncate":
				require.NoError(t, os.Truncate(name, 1))
			case "escape":
				require.NoError(t, os.Remove(name))
				require.NoError(t, os.WriteFile(filepath.Join(parent, "outside"), []byte("outside"), 0600))
				require.NoError(t, os.Symlink("../outside", name))
			}
			_, err = f.ReadAt(make([]byte, 3), 0)
			require.Error(t, err, "reopening must not read a replaced or unconfined file")
		})
	}
}

func TestConfinement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	require.NoError(t, os.Mkdir(root, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(parent, "outside"), []byte("outside"), 0600))
	fs := New(root, WithMmap())
	_, err := fs.Open("../outside")
	require.Error(t, err)
	_, err = fs.Chroot("..")
	require.Error(t, err)
	_, err = fs.Open(".")
	require.Error(t, err)
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require privileges on Windows")
	}
	require.NoError(t, os.Symlink("../outside", filepath.Join(root, "escape")))
	_, err = fs.Open("escape")
	require.Error(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "inside"), []byte("inside"), 0600))
	require.NoError(t, os.Symlink("inside", filepath.Join(root, "link")))
	f, err := fs.Open("link")
	require.NoError(t, err)
	defer f.Close()
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	require.Equal(t, "inside", string(data))
	entries, err := fs.ReadDir(".")
	require.NoError(t, err)
	require.Len(t, entries, 3)
}
