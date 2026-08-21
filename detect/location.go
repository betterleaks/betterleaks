package detect

import (
	"bytes"
	"slices"
	"strings"
	"sync"
)

const maxPooledLineOffsets = 16 * 1024

type lineOffsetBuffer struct {
	offsets []int
}

var lineOffsetPool = sync.Pool{
	New: func() any {
		return &lineOffsetBuffer{offsets: make([]int, 1, 128)}
	},
}

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

// computeLineOffsets returns a list of offsets for the beginning of
// each line in a file. It should always return at least []int{0}.
func computeLineOffsets(s string) []int {
	// init size to 1 so offsets[0] == 0
	offsets := make([]int, 1, max(1, len(s)/128))
	return appendLineOffsets(offsets, s)
}

func getLineOffsets(s string) *lineOffsetBuffer {
	buf := lineOffsetPool.Get().(*lineOffsetBuffer)
	buf.offsets = buf.offsets[:1]
	buf.offsets[0] = 0
	if wanted := max(1, len(s)/128); wanted > cap(buf.offsets) {
		buf.offsets = slices.Grow(buf.offsets, wanted-len(buf.offsets))
	}
	buf.offsets = appendLineOffsets(buf.offsets, s)
	return buf
}

func getLineOffsetsBytes(data []byte) *lineOffsetBuffer {
	buf := lineOffsetPool.Get().(*lineOffsetBuffer)
	buf.offsets = buf.offsets[:1]
	buf.offsets[0] = 0
	if wanted := max(1, len(data)/128); wanted > cap(buf.offsets) {
		buf.offsets = slices.Grow(buf.offsets, wanted-len(buf.offsets))
	}
	buf.offsets = appendLineOffsetsBytes(buf.offsets, data)
	return buf
}

func putLineOffsets(buf *lineOffsetBuffer) {
	// Avoid retaining a megabyte-scale []int after an unusually newline-dense
	// fragment. Typical source files remain reusable across rule evaluations.
	if cap(buf.offsets) > maxPooledLineOffsets {
		return
	}
	lineOffsetPool.Put(buf)
}

func appendLineOffsets(offsets []int, s string) []int {
	n := len(s)
	offset := 0

	for offset < n {
		i := strings.IndexByte(s[offset:], '\n')
		offset += i + 1
		if i == -1 || offset == n {
			break
		}
		offsets = append(offsets, offset)
	}

	return offsets
}

func appendLineOffsetsBytes(offsets []int, data []byte) []int {
	n := len(data)
	offset := 0
	for offset < n {
		i := bytes.IndexByte(data[offset:], '\n')
		offset += i + 1
		if i == -1 || offset == n {
			break
		}
		offsets = append(offsets, offset)
	}
	return offsets
}

// offsetToLineNumber returns the line number of an offset
func offsetToLineNumber(lineOffsets []int, offset int) int {
	index, found := slices.BinarySearch(lineOffsets, offset)
	if found || index == 0 {
		return index + 1
	} else {
		// Since it wasn't found, the index == the line number.
		return index
	}
}

func location(lineOffsets []int, raw string, matchIndex []int) Location {
	return locationForLength(lineOffsets, len(raw), matchIndex)
}

func locationForLength(lineOffsets []int, rawLength int, matchIndex []int) Location {
	startIndex := matchIndex[0]
	startLine := offsetToLineNumber(lineOffsets, startIndex)
	endIndex := matchIndex[1]
	endLine := offsetToLineNumber(lineOffsets, endIndex)
	endLineIndex := rawLength

	if endLine < len(lineOffsets) {
		// Since counting starts at 1 and indexing starts at 0, the index for
		// the next line is endLine.
		endLineIndex = lineOffsets[endLine]
	}

	return Location{
		startColumn:    startIndex - lineOffsets[startLine-1] + 1,
		startLine:      startLine,
		startLineIndex: lineOffsets[startLine-1],
		endColumn:      endIndex - lineOffsets[endLine-1],
		endLine:        endLine,
		endLineIndex:   endLineIndex,
	}
}
