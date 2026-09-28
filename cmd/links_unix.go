//go:build unix

package cmd

import (
	"os"
	"syscall"
)

// singleLink reports whether info describes a file with exactly one directory
// entry, so no hard link can present it under another path.
func singleLink(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 1
}
