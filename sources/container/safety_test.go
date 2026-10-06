package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return b.Bytes()
}

func TestNestedCompressionAndDepth(t *testing.T) {
	const secret = "NESTED_TEST_SECRET_abc123"
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "payload.gz.gz", content: string(gzipBytes(t, gzipBytes(t, []byte(secret))))})}, "tar"))
	dir := f.directory()
	fs, errs := collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 2})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/payload.gz.gz", secret)
	_, errs = collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 1})
	require.NotEmpty(t, errs)
	require.ErrorContains(t, errs[0], "archive depth")
	stop := errors.New("consumer stopped")
	calls := 0
	err := (&Source{Layouts: []string{dir}, MaxArchiveDepth: 8}).Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
		require.NoError(t, err)
		if fragment.Attr(sources.AttrResource) == ResourceFile {
			calls++
			return stop
		}
		return nil
	})
	require.ErrorIs(t, err, stop)
	require.Equal(t, 1, calls)
}

func TestArtifactDescriptorSizes(t *testing.T) {
	for _, size := range []int64{-1, 0, 1, 4095, 4096, 4097} {
		for _, limit := range []int64{16, 4096, 0} {
			t.Run(fmt.Sprintf("size=%d/limit=%d", size, limit), func(t *testing.T) {
				f := newFixture(t)
				payload := f.blob([]byte(strings.Repeat("x", 4096)), "application/octet-stream")
				payload.Size = size
				d := f.blob(jsonBytes(t, v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: f.blob([]byte("{}"), types.OCIEmptyJSON), Layers: []v1.Descriptor{payload}}), types.OCIManifestSchema1)
				f.setIndex(d)
				fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, MaxFileSize: limit, MaxArchiveDepth: 8})
				if size == 4096 && limit != 16 {
					require.Empty(t, errs)
				} else {
					require.NotEmpty(t, errs)
				}
				emitted := 0
				for _, v := range fs {
					if v.Attr(sources.AttrResource) == ResourceArtifact {
						emitted += len(v.Raw)
					}
				}
				if limit > 0 {
					require.LessOrEqual(t, int64(emitted), limit)
				}
			})
		}
	}
}

func TestManifestAndConfigDescriptorSizes(t *testing.T) {
	for _, part := range []string{"manifest", "config", "layer"} {
		t.Run(part, func(t *testing.T) {
			f := newFixture(t)
			d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "content"})}, "gzip")
			if part == "manifest" {
				d.Size++
			} else {
				var m v1.Manifest
				require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &m))
				if part == "config" {
					m.Config.Size++
				} else {
					m.Layers[0].Size++
				}
				d = f.blob(jsonBytes(t, m), types.OCIManifestSchema1)
			}
			f.setIndex(d)
			_, errs := collect(t, &Source{Layouts: []string{f.directory()}})
			require.NotEmpty(t, errs)
			require.Contains(t, fmt.Sprint(errs), "size")
		})
	}
}

func TestPlatformSelectionWithoutDescriptorPlatform(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%v", nested), func(t *testing.T) {
			f := newFixture(t)
			amd := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "amd", content: "amd-content"})}, "tar")
			arm := f.image("arm64", [][]byte{tarBytes(t, tarEntry{name: "arm", content: "arm-content"})}, "tar")
			amd.Platform = nil
			arm.Platform = nil
			if nested {
				arm = f.blob(jsonBytes(t, v1.IndexManifest{SchemaVersion: 2, Manifests: []v1.Descriptor{arm}}), types.OCIImageIndex)
			}
			f.setIndex(amd, arm)
			dir := f.directory()
			fs, errs := collect(t, &Source{Layouts: []string{dir}, Platforms: []string{"linux/amd64"}})
			require.Empty(t, errs)
			find(t, fs, ResourceFile, "/amd", "amd-content")
			for _, v := range fs {
				require.NotEqual(t, "/arm", v.Attr(sources.AttrPath))
			}
			_, errs = collect(t, &Source{Layouts: []string{dir}, Platforms: []string{"linux/riscv64"}})
			require.Len(t, errs, 1)
			require.ErrorContains(t, errs[0], "no runtime image matches")
		})
	}
}

func TestDecodedMetadataLimitAndCancellation(t *testing.T) {
	raw := jsonBytes(t, map[string]any{strings.Repeat("k", 32<<10): make([]int, 1000), "escape": "\n"})
	decodedBytes := 0
	r := &session{s: &Source{}, yield: func(f sources.Fragment, err error) error {
		require.NoError(t, err)
		if f.Attr(AttrRepresentation) == "decoded" {
			decodedBytes += len(f.Raw)
		}
		return nil
	}}
	require.ErrorContains(t, r.metadata(t.Context(), raw, "@config", ResourceConfig, nil), "decoded metadata exceeds")
	require.Zero(t, decodedBytes)
	ctx, cancel := context.WithCancel(t.Context())
	r.yield = func(f sources.Fragment, err error) error { cancel(); return nil }
	require.ErrorIs(t, r.metadata(ctx, []byte(`{"value":"escaped\nvalue"}`), "@config", ResourceConfig, nil), context.Canceled)
}

// Go's tar.Writer cannot write GNU sparse entries. Start with its GNU header,
// then encode one data extent after a hole and recalculate the tar checksum.
func sparseLayer(t *testing.T, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	require.NoError(t, w.WriteHeader(&tar.Header{Name: "sparse", Mode: 0600, Size: int64(len(content)), Format: tar.FormatGNU}))
	_, err := w.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	data := b.Bytes()
	data[156] = tar.TypeGNUSparse
	copy(data[386:398], fmt.Sprintf("%011o\x00", 32))
	copy(data[398:410], fmt.Sprintf("%011o\x00", len(content)))
	copy(data[483:495], fmt.Sprintf("%011o\x00", 32+len(content)))
	for i := 148; i < 156; i++ {
		data[i] = ' '
	}
	sum := 0
	for _, v := range data[:512] {
		sum += int(v)
	}
	copy(data[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return data
}

func TestGNUSparseLayerContentsAndSizeLimit(t *testing.T) {
	const secret = "SPARSE_TEST_SECRET_abc123"
	data := sparseLayer(t, secret)
	tr := tar.NewReader(bytes.NewReader(data))
	h, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, byte(tar.TypeGNUSparse), h.Typeflag)
	expanded, err := io.ReadAll(tr)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("\x00", 32)+secret, string(expanded))
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{data}, "gzip"))
	dir := f.directory()
	fs, errs := collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 8})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/sparse", secret)
	_, errs = collect(t, &Source{Layouts: []string{dir}, MaxFileSize: int64(len(secret))})
	require.NotEmpty(t, errs)
	require.ErrorContains(t, errs[0], "max-file-size")
}

func TestNestedCompressionTrailerValidation(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%v", broken), func(t *testing.T) {
			data := gzipBytes(t, tarBytes(t, tarEntry{name: "token.txt", content: "NESTED_TEST_SECRET_abc123"}))
			if broken {
				data[len(data)-8] ^= 0xff
			}
			f := newFixture(t)
			f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "bundle.tar.gz", content: string(data)}, tarEntry{name: "after", content: "still-scanned"})}, "tar"))
			fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8})
			if broken {
				require.NotEmpty(t, errs)
			} else {
				require.Empty(t, errs)
			}
			find(t, fs, ResourceFile, "/bundle.tar.gz!token.txt", "NESTED_TEST_SECRET_abc123")
			find(t, fs, ResourceFile, "/after", "still-scanned")
		})
	}
}

func TestDaemonFailureDiagnostic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock Docker executable")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\necho 'No such image: review:missing https://user:password@example.test/image?token=secret' >&2\nexit 1\n"), 0700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, errs := collect(t, &Source{Images: []string{"review:missing"}, Daemon: true})
	require.NotEmpty(t, errs)
	require.ErrorContains(t, errs[0], "docker image save failed")
	require.ErrorContains(t, errs[0], "No such image: review:missing")
	require.NotContains(t, errs[0].Error(), "password")
	require.NotContains(t, errs[0].Error(), "token=secret")
}

func TestDaemonDiagnosticBound(t *testing.T) {
	d := &daemonDiagnostic{}
	for range 3 {
		n, err := io.Copy(d, io.LimitReader(strings.NewReader(strings.Repeat("x", 10<<10)), 10<<10))
		require.NoError(t, err)
		require.Equal(t, int64(10<<10), n)
	}
	require.Equal(t, 16<<10, d.buffer.Len())
	require.True(t, strings.HasSuffix(d.String(), "[truncated]"))
}

// A reader may legally return data and EOF together. Verification failures
// must remain visible even if a tar parser uses that data and ignores its error.
type eofWithData struct{ *bytes.Reader }

func (r eofWithData) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func TestDigestErrorSurvivesFinalDataRead(t *testing.T) {
	reader, err := verifyingReader(eofWithData{bytes.NewReader([]byte("wrong"))}, sum([]byte("right")))
	require.NoError(t, err)
	p := make([]byte, 5)
	_, err = io.ReadFull(reader, p)
	require.NoError(t, err) // io.ReadFull intentionally discards errors with a full buffer.
	_, err = io.Copy(io.Discard, reader)
	require.ErrorContains(t, err, "digest mismatch")
}
