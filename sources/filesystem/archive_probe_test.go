package filesystem

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/internal/stream"
	"github.com/mholt/archives"
	"github.com/stretchr/testify/require"
)

// Compare the worker's probe with the registry on the same extensionless file.
// Reuse one probe across cases, just as a worker does across files.
func TestDiskArchiveProbe(t *testing.T) {
	var probe diskArchiveProbe
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "member", Mode: 0600,
		PAXRecords: map[string]string{"comment": strings.Repeat("x", stream.BufferSize+1)},
	}))
	require.NoError(t, tw.Close())

	check := func(t *testing.T, data []byte) {
		t.Helper()
		want, _, wantErr := archives.Identify(t.Context(), "", bytes.NewReader(data))
		path := filepath.Join(t.TempDir(), "opaque")
		require.NoError(t, os.WriteFile(path, data, 0600))
		f, err := os.Open(path)
		require.NoError(t, err)
		defer f.Close()
		got, r, err := identifyContent(t.Context(), f, &probe)
		if wantErr == nil {
			require.NoError(t, err)
			require.Equal(t, want.Extension(), got.Extension())
		} else {
			require.ErrorIs(t, wantErr, archives.NoMatch)
			require.ErrorIs(t, err, archives.NoMatch)
		}
		raw, err := io.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, data, raw)
	}
	for _, size := range []int{0, 512, stream.BufferSize - 1, stream.BufferSize, stream.BufferSize + 1} {
		check(t, bytes.Repeat([]byte("x"), size))
	}
	check(t, archive.Bytes())
	for _, name := range []string{"files.zip", "files.7z"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "archives", name))
		require.NoError(t, err)
		check(t, data)
	}
	check(t, []byte("Rar!\x1a\x07\x01\x00"))
	for _, codec := range []archives.Compression{
		archives.Gz{}, archives.Zlib{}, archives.Bz2{}, archives.Brotli{}, archives.Xz{},
		archives.Lz4{}, archives.Lzip{}, archives.MinLZ{}, archives.Sz{}, archives.Zstd{},
	} {
		t.Run(codec.Extension(), func(t *testing.T) {
			var out bytes.Buffer
			w, err := codec.OpenWriter(&out)
			require.NoError(t, err)
			_, err = w.Write(archive.Bytes())
			require.NoError(t, err)
			require.NoError(t, w.Close())
			check(t, out.Bytes())
		})
	}
}

// A ZIP with a prepended stub is identified by name. Extraction needs the
// original end-of-file offset after the worker has read ahead.
func TestDiskArchiveProbePrefixedZIP(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("member.txt")
	require.NoError(t, err)
	_, err = io.WriteString(w, "contents")
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	path := filepath.Join(t.TempDir(), "package.zip")
	require.NoError(t, os.WriteFile(path, append(bytes.Repeat([]byte("#"), stream.BufferSize+1), buf.Bytes()...), 0600))
	files := Files{Path: path, MaxArchiveDepth: 1, BuiltinArchiveFormats: true}
	var fragments []string
	require.NoError(t, files.Fragments(t.Context(), func(f sources.Fragment, err error) error {
		fragments = append(fragments, f.Raw)
		return err
	}))
	require.Equal(t, []string{"contents"}, fragments)
}
