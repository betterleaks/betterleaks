package gitfs

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/go-git/go-billy/v5"
)

// FilePool bounds open descriptors for unmapped, immutable pack/index files.
// Reads pin a descriptor until completion; only idle files can be evicted.
// Closing the returned files releases all resources owned by the pool.
type FilePool struct {
	mu    sync.Mutex
	ready *sync.Cond
	ctx   context.Context
	limit int
	clock uint64
	files map[*pooledFile]struct{}
}

func NewFilePool(ctx context.Context, limit int) *FilePool {
	if limit < 1 {
		panic("gitfs: file pool limit must be positive")
	}
	p := &FilePool{ctx: ctx, limit: limit, files: make(map[*pooledFile]struct{}, limit)} //nolint:exhaustruct // Synchronization and clock start empty.
	p.ready = sync.NewCond(&p.mu)
	return p
}

func (p *FilePool) open(fs *FS, name string) (billy.File, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.makeRoom(); err != nil {
		return nil, err
	}
	f, err := fs.open(name)
	if err != nil {
		return nil, err
	}
	if f.reader != nil {
		return f, nil // Mapped reads never acquire the pool lock.
	}
	result := &pooledFile{pool: p, base: fs.base, name: name, display: f.Name(), info: f.info, file: f.File} //nolint:exhaustruct // Cursor, readers and lifecycle start empty.
	p.files[result] = struct{}{}
	p.touch(result)
	return result, nil
}

// makeRoom runs with mu held. Opening is serialized to include temporary root
// descriptors in the bound: at most limit files plus one os.Root are open.
func (p *FilePool) makeRoom() error {
	var stop func() bool
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	for {
		if err := p.ctx.Err(); err != nil {
			return err
		}
		if len(p.files) < p.limit {
			return nil
		}
		var oldest *pooledFile
		for f := range p.files {
			if f.readers == 0 && (oldest == nil || f.used < oldest.used) {
				oldest = f
			}
		}
		if oldest != nil {
			err := oldest.file.Close()
			oldest.file = nil
			delete(p.files, oldest)
			return err
		}
		if stop == nil {
			stop = context.AfterFunc(p.ctx, func() {
				p.mu.Lock()
				p.ready.Broadcast()
				p.mu.Unlock()
			})
		}
		p.ready.Wait()
	}
}

func (p *FilePool) touch(f *pooledFile) {
	p.clock++
	f.used = p.clock
}

// pooledFile keeps its logical cursor across evictions. As with File, ReadAt
// supports concurrent callers, Read/Seek share a cursor, and Close follows all
// readers. All handle and lifecycle fields are protected by pool.mu.
type pooledFile struct {
	pool    *FilePool
	base    string
	name    string
	display string
	info    os.FileInfo
	offset  int64
	file    *os.File
	readers int
	used    uint64
	closed  bool
	err     error
}

func (f *pooledFile) acquire() (*os.File, error) {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	if err := p.ctx.Err(); err != nil {
		return nil, err
	}
	if f.file == nil {
		if err := p.makeRoom(); err != nil {
			return nil, err
		}
		// makeRoom can release the lock while waiting. Another reader may have
		// reopened this file in the meantime.
		if f.file == nil {
			file, info, err := openRegular(f.base, f.name)
			if err != nil {
				return nil, err
			}
			if !os.SameFile(f.info, info) || f.info.Size() != info.Size() || !f.info.ModTime().Equal(info.ModTime()) {
				file.Close()
				return nil, errors.New("git pack or index changed while scanning")
			}
			f.file = file
			p.files[f] = struct{}{}
		}
	}
	f.readers++
	return f.file, nil
}

func (f *pooledFile) release() {
	p := f.pool
	p.mu.Lock()
	f.readers--
	p.touch(f)
	if f.readers == 0 {
		p.ready.Broadcast()
	}
	p.mu.Unlock()
}

func (f *pooledFile) Name() string               { return f.display }
func (f *pooledFile) Stat() (os.FileInfo, error) { return f.info, nil }
func (f *pooledFile) ReadAt(b []byte, off int64) (int, error) {
	file, err := f.acquire()
	if err != nil {
		return 0, err
	}
	defer f.release()
	return file.ReadAt(b, off)
}
func (f *pooledFile) Read(b []byte) (int, error) {
	n, err := f.ReadAt(b, f.offset)
	f.offset += int64(n)
	return n, err
}
func (f *pooledFile) Seek(off int64, whence int) (int64, error) {
	f.pool.mu.Lock()
	defer f.pool.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = f.offset
	case io.SeekEnd:
		base = f.info.Size()
	default:
		return 0, os.ErrInvalid
	}
	if off < -base || off > int64(^uint64(0)>>1)-base {
		return 0, os.ErrInvalid
	}
	f.offset = base + off
	return f.offset, nil
}
func (f *pooledFile) Close() error {
	p := f.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	if !f.closed {
		f.closed = true
		if f.file != nil {
			f.err = f.file.Close()
			f.file = nil
			delete(p.files, f)
			p.ready.Broadcast()
		}
	}
	return f.err
}
func (*pooledFile) Write([]byte) (int, error) { return 0, os.ErrPermission }
func (*pooledFile) Truncate(int64) error      { return os.ErrPermission }
func (*pooledFile) Lock() error               { return os.ErrPermission }
func (*pooledFile) Unlock() error             { return os.ErrPermission }

var _ billy.File = (*pooledFile)(nil)
