//go:build cgo && betterleaks_ffi && (darwin || linux)

package main

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestScanFileRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	s := scannerForTest(t, testConfig, nil)
	result, err := s.scanFile([]byte(path), nil)
	var api *apiError
	if result != nil || !errors.As(err, &api) || api.status != statusInvalid {
		t.Fatalf("FIFO was not rejected: %s, %v", result, err)
	}
	// Also cover a FIFO reaching the opener (e.g. after a concurrent rename
	// between Stat and Open). O_NONBLOCK must let us inspect and reject it.
	file, err := openScanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().IsRegular() {
		t.Fatalf("cannot identify opened FIFO: %v", err)
	}
}
