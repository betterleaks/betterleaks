//go:build unix

package sources

import "syscall"

const gitMetadataNonblock = syscall.O_NONBLOCK
