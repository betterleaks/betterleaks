//go:build linux || darwin

package container

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

func TestConfigFIFO(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, syscall.Mkfifo(file, 0600))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := readConfigFile(ctx, file); done <- err }()
	select {
	case err := <-done:
		require.ErrorContains(t, err, "regular file")
	case <-ctx.Done():
		// Unblock a regressed implementation so the test leaves no reader behind.
		fd, err := syscall.Open(file, syscall.O_RDWR|syscall.O_NONBLOCK, 0600)
		require.NoError(t, err)
		defer syscall.Close(fd)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("opening a credential FIFO blocked")
	}
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestLocalContainerFIFOs(t *testing.T) {
	for _, part := range []string{"archive", "oci-layout", "index.json", "manifest", "config", "layer"} {
		t.Run(part, func(t *testing.T) {
			f := newFixture(t)
			d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "secret"})}, "tar")
			f.setIndex(d)
			dir := f.directory()
			s := &Source{Layouts: []string{dir}}
			file := filepath.Join(dir, part)
			if part == "archive" {
				s = &Source{Archives: []string{file}}
			} else {
				if part == "manifest" || part == "config" || part == "layer" {
					var m v1.Manifest
					require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &m))
					digest := d.Digest
					if part == "config" {
						digest = m.Config.Digest
					}
					if part == "layer" {
						digest = m.Layers[0].Digest
					}
					file = filepath.Join(dir, "blobs", strings.ReplaceAll(digest.String(), ":", "/"))
				}
				require.NoError(t, os.Remove(file))
			}
			require.NoError(t, syscall.Mkfifo(file, 0600))
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Fragments(ctx, func(_ sources.Fragment, err error) error { return err }) }()
			select {
			case err := <-done:
				require.ErrorContains(t, err, "regular file")
			case <-ctx.Done():
				fd, err := syscall.Open(file, syscall.O_RDWR|syscall.O_NONBLOCK, 0600)
				require.NoError(t, err)
				syscall.Close(fd)
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatal("container input open blocked on FIFO")
			}
		})
	}
}
