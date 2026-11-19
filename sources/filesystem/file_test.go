package filesystem

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/internal/stream"
	"github.com/klauspost/compress/gzip"
	"github.com/mholt/archives"
	"github.com/stretchr/testify/require"
)

func TestFileBrotliCompression(t *testing.T) {
	const content = "ARCHIVE_TEST_SECRET\n"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "token.txt", Mode: 0600, Size: int64(len(content))}))
	_, err := io.WriteString(tw, content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"plain.txt.br", []byte(content)},
		{"archive.tar.br", archive.Bytes()},
	} {
		var compressed bytes.Buffer
		w, err := (archives.Brotli{}).OpenWriter(&compressed)
		require.NoError(t, err)
		_, err = w.Write(tc.data)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		for _, detect := range []bool{false, true} {
			mode := "directory"
			if detect {
				mode = "container"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				s := File{Path: tc.name, Content: bytes.NewReader(compressed.Bytes()), MaxArchiveDepth: 8, DetectArchive: detect, StrictArchives: detect}
				var fragments []string
				require.NoError(t, s.Fragments(t.Context(), func(f sources.Fragment, err error) error {
					require.NoError(t, err)
					fragments = append(fragments, f.Raw)
					return nil
				}))
				require.Equal(t, []string{content}, fragments)
			})
		}
	}
}

// panicReader panics on the first Read, emulating a decompressor that blows up
// on malformed content after OpenReader already succeeded.
type panicReader struct {
	closed bool
}

func (p *panicReader) Read([]byte) (int, error) {
	panic("boom during read")
}

func (p *panicReader) Close() error {
	p.closed = true
	return nil
}

// panicDecompressor is an archives.Decompressor whose reader panics. When
// panicOnOpen is set, OpenReader itself panics instead.
type panicDecompressor struct {
	reader      io.ReadCloser
	openErr     error
	panicOnOpen bool
}

func (d *panicDecompressor) OpenReader(_ io.Reader) (io.ReadCloser, error) {
	if d.panicOnOpen {
		panic("boom during open")
	}
	return d.reader, d.openErr
}

type closePanicReader struct {
	io.Reader
}

func (*closePanicReader) Close() error {
	panic("boom during close")
}

func TestFile_decompressorFragments_recoversAndClosesReader(t *testing.T) {
	t.Run("panic while reading closes the inner reader", func(t *testing.T) {
		pr := &panicReader{}
		s := &File{Path: "evil.lz"}

		require.NotPanics(t, func() {
			s.decompressorFragments(
				t.Context(),
				&panicDecompressor{reader: pr},
				strings.NewReader("irrelevant"),
				func(sources.Fragment, error) error { return nil },
			)
		})

		require.True(t, pr.closed, "inner reader should be closed after a recovered panic")
	})

	t.Run("panic inside OpenReader is recovered", func(t *testing.T) {
		s := &File{Path: "evil.lz"}

		require.NotPanics(t, func() {
			s.decompressorFragments(
				t.Context(),
				&panicDecompressor{panicOnOpen: true},
				strings.NewReader("irrelevant"),
				func(sources.Fragment, error) error { return nil },
			)
		})
	})

	t.Run("typed nil reader returned with an error is not closed", func(t *testing.T) {
		var typedNilReader *panicReader
		yielded := false
		s := &File{Path: "evil.gz"}

		require.NotPanics(t, func() {
			s.decompressorFragments(
				t.Context(),
				&panicDecompressor{
					reader:  typedNilReader,
					openErr: errors.New("invalid header"),
				},
				strings.NewReader("irrelevant"),
				func(sources.Fragment, error) error {
					yielded = true
					return nil
				},
			)
		})

		require.False(t, yielded)
	})

	t.Run("panic while closing the inner reader is recovered", func(t *testing.T) {
		s := &File{Path: "evil.gz"}

		require.NotPanics(t, func() {
			s.decompressorFragments(
				t.Context(),
				&panicDecompressor{
					reader: &closePanicReader{Reader: strings.NewReader("")},
				},
				strings.NewReader("irrelevant"),
				func(sources.Fragment, error) error { return nil },
			)
		})
	})
}

// panicExtractor is an archives.Extractor whose Extract panics, emulating a
// decoder (e.g. rardecode) that blows up on a malformed archive header.
type panicExtractor struct{}

func (panicExtractor) Extract(context.Context, io.Reader, archives.FileHandler) error {
	panic("boom during extract")
}

func TestFile_extractorFragments_recoversPanic(t *testing.T) {
	s := &File{Path: "evil.rar"}

	require.NotPanics(t, func() {
		s.extractorFragments(
			t.Context(),
			panicExtractor{},
			strings.NewReader("irrelevant"),
			func(sources.Fragment, error) error { return nil },
		)
	})
}

// TestFile_Fragments_malformedRarDoesNotPanic drives the real 16-byte RAR5
// payload through the public entry point. Before the extractorFragments
// recover() guard, this panicked with "slice bounds out of range [3:1]" inside
// rardecode and killed the process.
func TestFile_Fragments_malformedRarDoesNotPanic(t *testing.T) {
	// RAR5 signature followed by 8 zero bytes -> block header parses size = 0.
	payload := "Rar!\x1a\x07\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	s := &File{
		Content:         strings.NewReader(payload),
		Path:            "evil.rar",
		MaxArchiveDepth: 5,
	}

	require.NotPanics(t, func() {
		err := s.Fragments(t.Context(), func(sources.Fragment, error) error { return nil })
		require.NoError(t, err)
	})
}

// TestFile_Fragments_malformedGzipDoesNotPanic drives a gzip header with an
// invalid compression method through the public entry point. OpenReader
// returns an error and an io.ReadCloser interface holding a nil *gzip.Reader.
func TestFile_Fragments_malformedGzipDoesNotPanic(t *testing.T) {
	payload := "\x1f\x8b\x02\x00\x00\x00\x00\x00\x00\x03"
	yielded := false
	s := &File{
		Content:         strings.NewReader(payload),
		Path:            "evil.gz",
		MaxArchiveDepth: 5,
	}

	require.NotPanics(t, func() {
		err := s.Fragments(t.Context(), func(sources.Fragment, error) error {
			yielded = true
			return nil
		})
		require.NoError(t, err)
	})
	require.False(t, yielded)
}

func TestFile_Fragments_marksFirstFragment(t *testing.T) {
	s := &File{
		Content: strings.NewReader(strings.Repeat("a", stream.BufferSize-2) + "\n\nbb\n\n"),
		Path:    "example.txt",
	}

	var fragments []sources.Fragment
	require.NoError(t, s.Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	}))

	require.Len(t, fragments, 2)
	require.Equal(t, strings.Repeat("a", stream.BufferSize-2)+"\n\n", fragments[0].Raw)
	require.Equal(t, "bb\n\n", fragments[1].Raw)
	require.Equal(t, "true", fragments[0].Attr(sources.AttrFSFirstFragment))
	require.Equal(t, "false", fragments[1].Attr(sources.AttrFSFirstFragment))
}

func TestFileLZ4StrictEndOfStream(t *testing.T) {
	const text = "Package: example\nDescription: package-index-test-content\n"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "Packages", Mode: 0600, Size: int64(len(text))}))
	_, err := tw.Write([]byte(text))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	for _, tc := range []struct {
		name    string
		content []byte
	}{
		{"plain", []byte(text)},
		{"empty", nil},
		{"tar", archive.Bytes()},
	} {
		for _, damage := range []string{"none", "checksum", "truncated"} {
			t.Run(tc.name+"/"+damage, func(t *testing.T) {
				var compressed bytes.Buffer
				w, err := (archives.Lz4{}).OpenWriter(&compressed)
				require.NoError(t, err)
				_, err = w.Write(tc.content)
				require.NoError(t, err)
				require.NoError(t, w.Close())
				data := compressed.Bytes()
				switch damage {
				case "checksum":
					data[len(data)-1] ^= 0xff
				case "truncated":
					data = data[:len(data)-2]
				}
				src := &File{Content: bytes.NewReader(data), Path: "Packages.lz4", DetectArchive: true, StrictArchives: true, MaxArchiveDepth: 8}
				var content strings.Builder
				var errs []error
				err = src.Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
					if err != nil {
						errs = append(errs, err)
					} else {
						content.WriteString(fragment.Raw)
					}
					return nil
				})
				require.NoError(t, err)
				if damage == "none" {
					require.Empty(t, errs)
					if tc.name != "empty" {
						require.Contains(t, content.String(), text)
					}
				} else {
					require.NotEmpty(t, errs)
				}
			})
		}
	}
}

func TestFileDetectArchivePlainGzipNames(t *testing.T) {
	const content = "auto\n/usr/share/man/man7/builtins.7.gz\n\n/usr/share/man/man7/bash-builtins.7.gz\n10\n"
	readers := map[string]func(*testing.T) io.Reader{
		"seekable": func(*testing.T) io.Reader {
			return strings.NewReader(content)
		},
		"stream": func(*testing.T) io.Reader {
			return io.LimitReader(strings.NewReader(content), int64(len(content)))
		},
		"tar member": func(t *testing.T) io.Reader {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			var header tar.Header
			header.Name = "member"
			header.Mode = 0600
			header.Size = int64(len(content))
			require.NoError(t, writer.WriteHeader(&header))
			_, err := io.WriteString(writer, content)
			require.NoError(t, err)
			require.NoError(t, writer.Close())
			reader := tar.NewReader(&archive)
			_, err = reader.Next()
			require.NoError(t, err)
			return reader
		},
	}
	for _, name := range []string{"builtins.7.gz", "plain.GZ", "plain.tgz", "plain.TGZ", "plain.tar.gz", "plain.txt"} {
		for kind, reader := range readers {
			t.Run(name+"/"+kind, func(t *testing.T) {
				var source File
				source.Content = reader(t)
				source.Path = name
				source.DetectArchive = true
				source.StrictArchives = true
				source.MaxArchiveDepth = 8
				var output strings.Builder
				err := source.Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
					if err != nil {
						return err
					}
					require.Equal(t, name, fragment.Attr(sources.AttrPath))
					output.WriteString(fragment.Raw)
					return nil
				})
				require.NoError(t, err)
				require.Equal(t, content, output.String())
			})
		}
	}
}

func TestFileDetectArchiveGzipIntegrity(t *testing.T) {
	const content = "plain gzip test content\n"
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err := io.WriteString(writer, content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	checksum := bytes.Clone(compressed.Bytes())
	checksum[len(checksum)-8] ^= 1
	for _, tc := range []struct {
		name    string
		path    string
		data    []byte
		wantErr error
	}{
		{
			name:    "valid gzip",
			path:    "payload.gz",
			data:    compressed.Bytes(),
			wantErr: nil,
		},
		{
			name:    "gzip without extension",
			path:    "payload",
			data:    compressed.Bytes(),
			wantErr: nil,
		},
		{
			name:    "invalid compression method",
			path:    "payload.gz",
			data:    []byte{0x1f, 0x8b, 0, 0, 0, 0, 0, 0, 0, 3},
			wantErr: gzip.ErrHeader,
		},
		{
			name:    "checksum failure",
			path:    "payload.gz",
			data:    checksum,
			wantErr: gzip.ErrChecksum,
		},
		{
			name:    "truncated gzip",
			path:    "payload.gz",
			data:    compressed.Bytes()[:compressed.Len()-4],
			wantErr: io.ErrUnexpectedEOF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var source File
			source.Content = bytes.NewReader(tc.data)
			source.Path = tc.path
			source.DetectArchive = true
			source.StrictArchives = true
			source.MaxArchiveDepth = 8
			var output strings.Builder
			err := source.Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
				if err == nil {
					output.WriteString(fragment.Raw)
				}
				return err
			})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, content, output.String())
		})
	}
}
