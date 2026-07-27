package sources

import (
	"context"
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
	reader      *panicReader
	panicOnOpen bool
}

func (d *panicDecompressor) OpenReader(_ io.Reader) (io.ReadCloser, error) {
	if d.panicOnOpen {
		panic("boom during open")
	}
	return d.reader, nil
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
