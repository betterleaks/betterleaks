package detect

import (
	"slices"
	"strings"
)

// matchLocation is the detector's internal position data for a regex match.
type matchLocation struct {
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
	n := len(s)
	// init size to 1 so offsets[0] == 0
	offsets := make([]int, 1, max(1, n/128))
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

func location(lineOffsets []int, raw string, matchIndex []int) matchLocation {
	startIndex := matchIndex[0]
	startLine := offsetToLineNumber(lineOffsets, startIndex)
	endIndex := matchIndex[1]
	endLine := offsetToLineNumber(lineOffsets, endIndex)
	endLineIndex := len(raw)

	if endLine < len(lineOffsets) {
		// Since counting starts at 1 and indexing starts at 0, the index for
		// the next line is endLine.
		endLineIndex = lineOffsets[endLine]
	}

	return matchLocation{
		startColumn:    startIndex - lineOffsets[startLine-1] + 1,
		startLine:      startLine,
		startLineIndex: lineOffsets[startLine-1],
		endColumn:      endIndex - lineOffsets[endLine-1],
		endLine:        endLine,
		endLineIndex:   endLineIndex,
	}
}
