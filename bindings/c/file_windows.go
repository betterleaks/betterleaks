//go:build cgo && betterleaks_ffi && windows

package main

import "os"

func openScanFile(path string) (*os.File, error) {
	return os.Open(path)
}
