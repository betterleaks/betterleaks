// Package gitfs adapts os.Root to go-billy v5 for confined, read-only Git reads.
package gitfs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/go-git/go-billy/v5"
)

type Option func(*FS)

func WithMmap() Option { return func(f *FS) { f.mmap = true } }

// WithFilePool bounds the descriptors retained when mapping is unavailable.
// A pool can be shared by filesystems rooted in different object directories.
func WithFilePool(pool *FilePool) Option { return func(f *FS) { f.pool = pool } }

type FS struct {
	base string
	mmap bool
	pool *FilePool
}

func New(base string, opts ...Option) *FS {
	f := &FS{base: base, mmap: false, pool: nil}
	for _, opt := range opts {
		opt(f)
	}
	return f
}
func (f *FS) Root() string                         { return f.base }
func (*FS) Join(parts ...string) string            { return filepath.Join(parts...) }
func (*FS) Capabilities() billy.Capability         { return billy.ReadCapability | billy.SeekCapability }
func (f *FS) Open(name string) (billy.File, error) { return f.OpenFile(name, os.O_RDONLY, 0) }
func (f *FS) OpenFile(name string, flag int, _ os.FileMode) (billy.File, error) {
	if flag & ^NonBlocking != os.O_RDONLY {
		return nil, os.ErrPermission
	}
	if f.pool != nil {
		return f.pool.open(f, name)
	}
	return f.open(name)
}

func openRegular(base, name string) (*os.File, os.FileInfo, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	file, err := root.OpenFile(name, os.O_RDONLY|NonBlocking, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, errors.Join(err, errors.New("git storage is not a regular file"))
	}
	return file, info, nil
}

func (f *FS) open(name string) (*File, error) {
	file, info, err := openRegular(f.base, name)
	if err != nil {
		return nil, err
	}
	result := &File{File: file, info: info} //nolint:exhaustruct // Mapping and close bookkeeping start empty.
	if f.mmap && info.Size() > 0 && info.Size() <= int64(int(^uint(0)>>1)) {
		if data, err := mapFile(file, int(info.Size())); err == nil {
			result.data = data
			result.reader = bytes.NewReader(data)
			file.Close()
		}
	}
	return result, nil
}
func (f *FS) ReadDir(name string) ([]os.FileInfo, error) {
	root, err := os.OpenRoot(f.base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.OpenFile(name, os.O_RDONLY|NonBlocking, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	info := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		i, err := e.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue // Preserve the remaining entries during concurrent ref updates.
		}
		if err != nil {
			return nil, err
		}
		info = append(info, i)
	}
	slices.SortFunc(info, func(a, b os.FileInfo) int { return strings.Compare(a.Name(), b.Name()) })
	return info, nil
}
func (f *FS) Stat(name string) (os.FileInfo, error) {
	root, err := os.OpenRoot(f.base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Stat(name)
}
func (f *FS) Lstat(name string) (os.FileInfo, error) {
	root, err := os.OpenRoot(f.base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Lstat(name)
}
func (f *FS) Readlink(name string) (string, error) {
	root, err := os.OpenRoot(f.base)
	if err != nil {
		return "", err
	}
	defer root.Close()
	return root.Readlink(name)
}
func (f *FS) Chroot(name string) (billy.Filesystem, error) {
	root, err := os.OpenRoot(f.base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	defer child.Close()
	return &FS{base: child.Name(), mmap: f.mmap, pool: f.pool}, nil
}
func (*FS) Create(string) (billy.File, error)           { return nil, os.ErrPermission }
func (*FS) TempFile(string, string) (billy.File, error) { return nil, os.ErrPermission }
func (*FS) Rename(string, string) error                 { return os.ErrPermission }
func (*FS) Remove(string) error                         { return os.ErrPermission }
func (*FS) MkdirAll(string, os.FileMode) error          { return os.ErrPermission }
func (*FS) Symlink(string, string) error                { return os.ErrPermission }

// File closes the OS descriptor after mapping. Even repositories with many
// packs then need virtual mappings, not one permanently open fd per pack.
// ReadAt is concurrent; Read and Seek are for a single caller, like os.File's
// shared offset. Close must follow the completion of all readers.
type File struct {
	*os.File
	info   os.FileInfo
	data   []byte
	reader *bytes.Reader
	once   sync.Once
	err    error
}

func (f *File) Stat() (os.FileInfo, error) { return f.info, nil }
func (f *File) ReadAt(b []byte, off int64) (int, error) {
	if f.reader != nil {
		return f.reader.ReadAt(b, off)
	}
	return f.File.ReadAt(b, off)
}
func (f *File) Read(b []byte) (int, error) {
	if f.reader != nil {
		return f.reader.Read(b)
	}
	return f.File.Read(b)
}
func (f *File) Seek(off int64, whence int) (int64, error) {
	if f.reader != nil {
		return f.reader.Seek(off, whence)
	}
	return f.File.Seek(off, whence)
}
func (f *File) Close() error {
	f.once.Do(func() {
		if f.reader != nil {
			f.err = unmapFile(f.data)
			f.reader = nil
			f.data = nil
		} else {
			f.err = f.File.Close()
		}
	})
	return f.err
}
func (*File) Write([]byte) (int, error) { return 0, os.ErrPermission }
func (*File) Truncate(int64) error      { return os.ErrPermission }
func (*File) Lock() error               { return os.ErrPermission }
func (*File) Unlock() error             { return os.ErrPermission }

var _ billy.Filesystem = (*FS)(nil)
var _ io.ReaderAt = (*File)(nil)
