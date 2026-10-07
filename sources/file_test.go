package sources

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/mholt/archives"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// Both directory and container scans must expand recognized archives and
// nested compression, including the common .tgz alias.
func TestFile_ArchiveDiscovery(t *testing.T) {
	const content = "ARCHIVE_TEST_SECRET\n"
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "token.txt", Mode: 0600, Size: int64(len(content))}))
	_, err := io.WriteString(tw, content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	compress := func(data []byte) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, err := w.Write(data)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		return b.Bytes()
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"archive.tgz", compress(archive.Bytes())},
		{"nested.gz", compress(compress([]byte(content)))},
		{"archive.tar.gz", compress(archive.Bytes())},
		{"plain.txt.gz", compress([]byte(content))},
	} {
		for _, detect := range []bool{false, true} {
			mode := "directory"
			if detect {
				mode = "container"
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				s := File{Path: tc.name, Content: bytes.NewReader(tc.data), MaxArchiveDepth: 8, DetectArchive: detect, StrictArchives: detect}
				var fragments []string
				require.NoError(t, s.Fragments(t.Context(), func(f Fragment, err error) error {
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
				func(Fragment, error) error { return nil },
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
				func(Fragment, error) error { return nil },
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
				func(Fragment, error) error {
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
				func(Fragment, error) error { return nil },
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
			func(Fragment, error) error { return nil },
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
		err := s.Fragments(t.Context(), func(Fragment, error) error { return nil })
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
		err := s.Fragments(t.Context(), func(Fragment, error) error {
			yielded = true
			return nil
		})
		require.NoError(t, err)
	})
	require.False(t, yielded)
}

func TestFile_Fragments_marksFirstFragment(t *testing.T) {
	s := &File{
		Content: strings.NewReader("aa\n\nbb\n\n"),
		Path:    "example.txt",
		Buffer:  make([]byte, 4),
	}

	var fragments []Fragment
	require.NoError(t, s.Fragments(t.Context(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		fragments = append(fragments, fragment)
		return nil
	}))

	require.Len(t, fragments, 2)
	require.Equal(t, "true", fragments[0].Attr(AttrFSFirstFragment))
	require.Equal(t, "false", fragments[1].Attr(AttrFSFirstFragment))
}

func TestFileStrictArchiveFailures(t *testing.T) {
	var tarData bytes.Buffer
	tw := tar.NewWriter(&tarData)
	for _, name := range []string{"first.txt", "second.txt"} {
		data := strings.Repeat("content\n", 10000)
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}))
		_, err := io.WriteString(tw, data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	_, err := gw.Write(tarData.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	corrupt := bytes.Clone(compressed.Bytes())
	corrupt[len(corrupt)-8] ^= 1 // Invalid gzip CRC, after the tar end marker.

	for _, tc := range []struct {
		name    string
		data    []byte
		depth   int
		message string
	}{
		{"checksum.tar.gz", corrupt, 8, "checksum"},
		{"depth.tar", tarData.Bytes(), 0, "exceeds max archive depth"},
	} {
		for _, stopOnError := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stop=%v", tc.name, stopOnError), func(t *testing.T) {
				logger := zerolog.Nop()
				s := File{Path: tc.name, Content: bytes.NewReader(tc.data), StrictArchives: true, MaxArchiveDepth: tc.depth, Logger: &logger}
				var reported []error
				stop := errors.New("callback stopped scan")
				err := s.Fragments(t.Context(), func(_ Fragment, err error) error {
					if err != nil {
						reported = append(reported, err)
						if stopOnError {
							return stop
						}
					}
					return nil
				})
				require.NotEmpty(t, reported)
				require.Contains(t, reported[0].Error(), tc.message)
				if stopOnError {
					require.ErrorIs(t, err, stop)
					require.Len(t, reported, 1)
				} else {
					require.NoError(t, err) // Error callbacks were accepted by the caller.
				}
			})
		}
	}

	t.Run("callback stops valid archive", func(t *testing.T) {
		logger := zerolog.Nop()
		s := File{Path: "valid.tar.gz", Content: bytes.NewReader(compressed.Bytes()), StrictArchives: true, MaxArchiveDepth: 8, Logger: &logger}
		stop := errors.New("stop after first finding")
		callbacks := 0
		err := s.Fragments(t.Context(), func(f Fragment, err error) error {
			callbacks++
			require.NoError(t, err)
			require.Contains(t, f.Attr(AttrPath), "first.txt")
			return stop
		})
		require.ErrorIs(t, err, stop)
		require.Equal(t, 1, callbacks)
	})
}

func TestFileDiagnosticsUseSuppliedLogger(t *testing.T) {
	var global bytes.Buffer
	original := logging.Logger
	logging.Logger = zerolog.New(&global).Level(zerolog.DebugLevel)
	t.Cleanup(func() { logging.Logger = original })
	readErr := errors.New("read failed")
	for _, tc := range []struct {
		name    string
		content io.Reader
		message string
	}{
		{"binary", strings.NewReader("PK\x03\x04" + strings.Repeat("\x00", 32)), "skipping binary file"},
		{"read-error", readerFunc(func(p []byte) (int, error) { return copy(p, "content\n\n"), readErr }), "issue reading file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := zerolog.New(&output).Level(zerolog.DebugLevel)
			s := File{Path: "test.txt", Content: tc.content, Logger: &logger}
			_ = s.Fragments(t.Context(), func(_ Fragment, err error) error { return err })
			require.Contains(t, output.String(), tc.message)
			require.Contains(t, output.String(), "test.txt")
			require.Empty(t, global.String())
		})
	}
}
