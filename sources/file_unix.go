//go:build unix

package sources

import (
	"io"
	"syscall"
)

// rawFile is a read-only file handle backed directly by a file descriptor.
//
// os.Open costs six syscalls on Linux (openat, four fcntl calls to toggle
// O_NONBLOCK, and a failed epoll_ctl) plus a finalizer; a directory scan opens
// every file exactly once and reads it sequentially, so it needs none of that.
// rawFile keeps to openat/read/close and the pread/lseek that archive
// extractors require.
type rawFile struct {
	fd int
}

func openFile(path string) (*rawFile, error) {
	for {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		return &rawFile{fd: fd}, nil
	}
}

func (f *rawFile) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := syscall.Read(f.fd, p)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func (f *rawFile) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := syscall.Pread(f.fd, p, off)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.EOF
		}
		total += n
		off += int64(n)
		p = p[n:]
	}
	return total, nil
}

func (f *rawFile) Seek(offset int64, whence int) (int64, error) {
	return syscall.Seek(f.fd, offset, whence)
}

// Size returns the file size from the descriptor without a path lookup.
func (f *rawFile) Size() (int64, error) {
	var st syscall.Stat_t
	for {
		err := syscall.Fstat(f.fd, &st)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		return st.Size, nil
	}
}

func (f *rawFile) Close() error {
	return syscall.Close(f.fd)
}
