//go:build !unix

package cmd

import "os"

// singleLink is unknown without a unix stat, so callers keep the stat-based
// report guard.
func singleLink(os.FileInfo) bool { return false }
