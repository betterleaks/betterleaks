//go:build unix

package gitfs

import (
	"os"

	"golang.org/x/sys/unix"
)

const NonBlocking = unix.O_NONBLOCK

func mapFile(f *os.File, size int) ([]byte, error) {
	return unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ, unix.MAP_SHARED)
}
func unmapFile(b []byte) error { return unix.Munmap(b) }
