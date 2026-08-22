package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocation(t *testing.T) {
	t.Run("computeLineOffsets", func(t *testing.T) {
		tests := []struct {
			name     string
			text     string
			expected []int
		}{
			{
				name:     "no newline",
				text:     "Hello world!",
				expected: []int{0},
			},
			{
				name:     "newline at end",
				text:     "Hello world!\n",
				expected: []int{0},
			},
			{
				name:     "CRLF at end",
				text:     "Hello world!\r\n",
				expected: []int{0},
			},
			{
				name:     "newline in middle",
				text:     "Hello\nworld!",
				expected: []int{0, 6},
			},
			{
				name:     "CRLF in middle",
				text:     "Hello\r\nworld!",
				expected: []int{0, 7},
			},
			{
				name:     "newline in middle and end",
				text:     "Hello\nworld!\n",
				expected: []int{0, 6},
			},
			{
				name:     "CRLF in middle and end",
				text:     "Hello\r\nworld!\r\n",
				expected: []int{0, 7},
			},
			{
				name:     "Multiple newlines together",
				text:     "Hello\n\nworld\n",
				expected: []int{0, 6, 7},
			},
			{
				name:     "Multiple newlines and CRLFS together",
				text:     "Hello\n\r\nworld\n",
				expected: []int{0, 6, 8},
			},
			{
				name:     "newline at beginning",
				text:     "\nHello world!",
				expected: []int{0, 1},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				actual := computeLineOffsets(tt.text)
				assert.Equal(t, actual, tt.expected, "%#v != %#v for %q", actual, tt.expected, tt.text)
			})
		}
	})

	t.Run("location", func(t *testing.T) {
		//      0                                        40               56                                                                       128
		//      |                                        |                |                                                                        |
		raw := "111111111111111111111111111111111111111\n222222222222222\n33333333333333333333333333333333333333333333333333333333333333333333333\n4444"
		lineOffsets := computeLineOffsets(raw)
		require.Equal(t, lineOffsets, []int{0, 40, 56, 128})

		tests := []struct {
			lineOffsets  []int
			matchStart   int
			matchEnd     int
			wantLocation Location
		}{
			{
				lineOffsets: lineOffsets,
				matchStart:  35,
				matchEnd:    44,
				wantLocation: Location{
					startLine:      1,
					startColumn:    36,
					endLine:        2,
					endColumn:      4,
					startLineIndex: 0,
					endLineIndex:   56,
				},
			},
			{
				lineOffsets: lineOffsets,
				matchStart:  25,
				matchEnd:    38,
				wantLocation: Location{
					startLine:      1,
					startColumn:    26,
					endLine:        1,
					endColumn:      38,
					startLineIndex: 0,
					endLineIndex:   40,
				},
			},
			{
				lineOffsets: lineOffsets,
				matchStart:  56,
				matchEnd:    129,
				wantLocation: Location{
					startLine:      3,
					startColumn:    1,
					endLine:        4,
					endColumn:      1,
					startLineIndex: 56,
					endLineIndex:   len(raw),
				},
			},
		}

		for _, tt := range tests {
			matchIndex := []int{tt.matchStart, tt.matchEnd}
			loc := location(tt.lineOffsets, raw, matchIndex)
			assert.Equal(t, tt.wantLocation, loc)
		}
	})
}
