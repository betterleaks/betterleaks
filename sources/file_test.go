package sources

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/mholt/archives"
	"github.com/stretchr/testify/require"
)

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
