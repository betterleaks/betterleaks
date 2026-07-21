package detect

import (
	"slices"
	"strings"
)

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

// findLineOffsets returns a list of offsets for the beginning of
// each line in a file
func findLineOffsets(s string) []int {
	offsets := make([]int, 1, max(1, len(s)/128))
	offset := 1
	n := len(s)
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

// findOffsetLine returns the line a specific offset is on
func findOffsetLine(lineOffsets []int, offset int) int {
	index, found := slices.BinarySearch(lineOffsets, offset)
	if found || index == 0 {
		return index + 1
	} else {
		// since it wasn't found the line before is just the index
		return index
	}
}

func location(lineOffsets []int, raw string, matchIndex []int) Location {
	startIndex := matchIndex[0]
	startLine := findOffsetLine(lineOffsets, startIndex)
	endIndex := matchIndex[1]
	endLine := findOffsetLine(lineOffsets, endIndex)
	endLineIndex := len(raw)

	if endLine < len(lineOffsets) {
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
