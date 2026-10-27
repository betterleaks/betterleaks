//go:build unix

package gogit

import "syscall"

// Opening a FIFO for reading otherwise waits for a writer.
const nonBlocking = syscall.O_NONBLOCK
