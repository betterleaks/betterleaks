package sources

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/mholt/archives"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
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

// encodeWithBOM transcodes text to the given UTF-16 byte order with a
// leading BOM, mirroring what Windows tools commonly write.
func encodeWithBOM(t *testing.T, text string, order unicode.Endianness) []byte {
	t.Helper()
	encoded, _, err := transform.String(unicode.UTF16(order, unicode.UseBOM).NewEncoder(), text)
	require.NoError(t, err)
	return []byte(encoded)
}

// collectFragments runs Fragments and concatenates every fragment's raw text.
func collectFragments(t *testing.T, s *File) string {
	t.Helper()
	var out strings.Builder
	require.NoError(t, s.Fragments(t.Context(), func(f Fragment, err error) error {
		require.NoError(t, err)
		out.WriteString(f.Raw)
		return nil
	}))
	return out.String()
}

func TestFile_Fragments_decodesUTF16(t *testing.T) {
	const secret = "BSA111222333444555666777888999000111"
	text := "api_key = " + secret + "\n"

	t.Run("UTF-16 LE with BOM", func(t *testing.T) {
		content := encodeWithBOM(t, text, unicode.LittleEndian)
		s := &File{Content: strings.NewReader(string(content)), Path: "secret.txt"}
		require.Contains(t, collectFragments(t, s), secret)
	})

	t.Run("UTF-16 BE with BOM", func(t *testing.T) {
		content := encodeWithBOM(t, text, unicode.BigEndian)
		s := &File{Content: strings.NewReader(string(content)), Path: "secret.txt"}
		require.Contains(t, collectFragments(t, s), secret)
	})

	t.Run("plain UTF-8 with no BOM is unchanged", func(t *testing.T) {
		s := &File{Content: strings.NewReader(text), Path: "secret.txt"}
		require.Equal(t, text, collectFragments(t, s))
	})

	t.Run("UTF-8 with BOM has BOM stripped and still matches", func(t *testing.T) {
		content := "\xEF\xBB\xBF" + text
		s := &File{Content: strings.NewReader(content), Path: "secret.txt"}
		require.Contains(t, collectFragments(t, s), secret)
	})

	t.Run("empty content produces no fragments", func(t *testing.T) {
		s := &File{Content: strings.NewReader(""), Path: "empty.txt"}
		require.Empty(t, collectFragments(t, s))
	})

	t.Run("UTF-16 content spanning multiple buffer reads decodes correctly", func(t *testing.T) {
		var sb strings.Builder
		for i := 0; i < 5000; i++ {
			sb.WriteString("filler line of text\n")
		}
		sb.WriteString("api_key = " + secret + "\n")
		large := sb.String()
		require.Greater(t, len(large), defaultBufferSize, "test content must span multiple internal buffer reads")

		content := encodeWithBOM(t, large, unicode.LittleEndian)
		s := &File{Content: strings.NewReader(string(content)), Path: "large.txt"}
		require.Contains(t, collectFragments(t, s), secret)
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
