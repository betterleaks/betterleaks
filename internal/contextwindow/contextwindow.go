// Package contextwindow parses directional line and character window specifications.
package contextwindow

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Mode determines how a context window is interpreted.
type Mode int

const (
	ModeNone Mode = iota
	ModeCols
	ModeBox
)

// Spec describes directional context boundaries around a match.
type Spec struct {
	Mode        Mode
	ColsBefore  int
	ColsAfter   int
	LinesBefore int
	LinesAfter  int
}

// IsZero reports whether no window is configured.
func (s Spec) IsZero() bool {
	return s.Mode == ModeNone
}

type direction struct {
	before     int
	after      int
	bidirected int
}

var tokenRE = regexp.MustCompile(`(?i)^([+-]?)(\d+)([CL]?)$`)

// Parse parses the grammar shared by --match-context and component within fields.
func Parse(value string) (Spec, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return Spec{}, nil
	}

	var cols, lines direction
	hasLines, hasCols := false, false

	for token := range strings.SplitSeq(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return Spec{}, fmt.Errorf("empty token in context window %q", value)
		}

		matches := tokenRE.FindStringSubmatch(token)
		if matches == nil {
			return Spec{}, fmt.Errorf("invalid context window token %q", token)
		}

		directionMarker := matches[1]
		amount, err := strconv.Atoi(matches[2])
		if err != nil {
			return Spec{}, fmt.Errorf("invalid context window amount %q: %w", matches[2], err)
		}
		unit := strings.ToUpper(matches[3])
		if unit == "" {
			unit = "C"
		}

		switch unit {
		case "L":
			hasLines = true
			amount = max(amount-1, 0)
			applyDirection(&lines, directionMarker, amount)
		case "C":
			hasCols = true
			applyDirection(&cols, directionMarker, amount)
		default:
			return Spec{}, fmt.Errorf("invalid context window unit %q", unit)
		}
	}

	spec := Spec{
		ColsBefore: max(cols.before, cols.bidirected),
		ColsAfter:  max(cols.after, cols.bidirected),
	}
	if hasLines {
		spec.Mode = ModeBox
		spec.LinesBefore = max(lines.before, lines.bidirected)
		spec.LinesAfter = max(lines.after, lines.bidirected)
	} else if hasCols {
		spec.Mode = ModeCols
	} else {
		return Spec{}, fmt.Errorf("invalid context window %q", value)
	}

	return spec, nil
}

func applyDirection(target *direction, marker string, amount int) {
	switch marker {
	case "-":
		target.before = max(target.before, amount)
	case "+":
		target.after = max(target.after, amount)
	default:
		target.bidirected = max(target.bidirected, amount)
	}
}

// Extract returns the context selected by spec around matchIndex in raw.
func Extract(raw string, matchIndex []int, spec Spec) string {
	if spec.IsZero() || len(raw) == 0 {
		return ""
	}

	switch spec.Mode {
	case ModeCols:
		start := max(matchIndex[0]-spec.ColsBefore, 0)
		end := min(matchIndex[1]+spec.ColsAfter, len(raw))
		return raw[start:end]
	case ModeBox:
		return extractBox(raw, matchIndex, spec)
	default:
		return ""
	}
}

// ExtractBytes is the byte-slice form of Extract. Returned data may alias raw;
// callers that retain it beyond the source callback must copy it.
func ExtractBytes(raw []byte, matchIndex []int, spec Spec) []byte {
	if spec.IsZero() || len(raw) == 0 {
		return nil
	}

	switch spec.Mode {
	case ModeCols:
		start := max(matchIndex[0]-spec.ColsBefore, 0)
		end := min(matchIndex[1]+spec.ColsAfter, len(raw))
		return raw[start:end]
	case ModeBox:
		return extractBoxBytes(raw, matchIndex, spec)
	default:
		return nil
	}
}

func extractBoxBytes(raw []byte, matchIndex []int, spec Spec) []byte {
	matchStart, matchEnd := matchIndex[0], matchIndex[1]
	lineStart := bytes.LastIndexByte(raw[:matchStart], '\n') + 1
	lineEnd := bytes.IndexByte(raw[matchEnd:], '\n')
	if lineEnd == -1 {
		lineEnd = len(raw)
	} else {
		lineEnd += matchEnd
	}

	contextStart := lineStart
	for i := 0; i < spec.LinesBefore && contextStart > 0; i++ {
		contextStart = bytes.LastIndexByte(raw[:contextStart-1], '\n') + 1
	}
	contextEnd := lineEnd
	for i := 0; i < spec.LinesAfter && contextEnd < len(raw); i++ {
		nextNewline := bytes.IndexByte(raw[contextEnd+1:], '\n')
		if nextNewline == -1 {
			contextEnd = len(raw)
			break
		}
		contextEnd += nextNewline + 1
	}

	extracted := raw[contextStart:contextEnd]
	if !bytes.Contains(raw[matchStart:matchEnd], []byte{'\n'}) && (spec.ColsBefore > 0 || spec.ColsAfter > 0) {
		matchColumn := matchStart - lineStart
		matchLength := matchEnd - matchStart
		extracted = clipLinesBytes(
			extracted,
			max(matchColumn-spec.ColsBefore, 0),
			matchColumn+matchLength+spec.ColsAfter,
		)
	}
	return extracted
}

func clipLinesBytes(text []byte, clipStart, clipEnd int) []byte {
	outputLen := 0
	changed := false
	remaining := text
	for {
		newline := bytes.IndexByte(remaining, '\n')
		line := remaining
		if newline >= 0 {
			line = remaining[:newline]
		}
		start := clipStart
		if len(line) <= start {
			start = 0
		}
		end := min(clipEnd, len(line))
		outputLen += end - start
		changed = changed || start != 0 || end != len(line)
		if newline < 0 {
			break
		}
		outputLen++
		remaining = remaining[newline+1:]
	}
	if !changed {
		return text
	}

	result := make([]byte, 0, outputLen)
	remaining = text
	for {
		newline := bytes.IndexByte(remaining, '\n')
		line := remaining
		if newline >= 0 {
			line = remaining[:newline]
		}
		start := clipStart
		if len(line) <= start {
			start = 0
		}
		result = append(result, line[start:min(clipEnd, len(line))]...)
		if newline < 0 {
			break
		}
		result = append(result, '\n')
		remaining = remaining[newline+1:]
	}
	return result
}

func extractBox(raw string, matchIndex []int, spec Spec) string {
	matchStart, matchEnd := matchIndex[0], matchIndex[1]

	lineStart := strings.LastIndexByte(raw[:matchStart], '\n') + 1
	lineEnd := strings.IndexByte(raw[matchEnd:], '\n')
	if lineEnd == -1 {
		lineEnd = len(raw)
	} else {
		lineEnd += matchEnd
	}

	contextStart := lineStart
	for i := 0; i < spec.LinesBefore && contextStart > 0; i++ {
		contextStart = strings.LastIndexByte(raw[:contextStart-1], '\n') + 1
	}

	contextEnd := lineEnd
	for i := 0; i < spec.LinesAfter && contextEnd < len(raw); i++ {
		nextNewline := strings.IndexByte(raw[contextEnd+1:], '\n')
		if nextNewline == -1 {
			contextEnd = len(raw)
			break
		}
		contextEnd += nextNewline + 1
	}

	extracted := raw[contextStart:contextEnd]

	// Column clipping only makes sense for single-line matches. For multiline
	// matches, the first-line column offset does not apply to subsequent lines.
	if !strings.ContainsRune(raw[matchStart:matchEnd], '\n') && (spec.ColsBefore > 0 || spec.ColsAfter > 0) {
		matchColumn := matchStart - lineStart
		matchLength := matchEnd - matchStart
		clipStart := max(matchColumn-spec.ColsBefore, 0)
		clipEnd := matchColumn + matchLength + spec.ColsAfter
		extracted = clipLines(extracted, clipStart, clipEnd)
	}

	return extracted
}

// clipLines applies the same column window to every line. Most source lines
// already fit in the requested window; in that case return the original view
// instead of allocating a split slice and a joined copy.
func clipLines(text string, clipStart, clipEnd int) string {
	outputLen := 0
	changed := false
	remaining := text
	for {
		newline := strings.IndexByte(remaining, '\n')
		line := remaining
		if newline >= 0 {
			line = remaining[:newline]
		}

		start := clipStart
		if len(line) <= start {
			start = 0
		}
		end := min(clipEnd, len(line))
		outputLen += end - start
		if start != 0 || end != len(line) {
			changed = true
		}

		if newline < 0 {
			break
		}
		outputLen++ // Preserve the separator, including a trailing newline.
		remaining = remaining[newline+1:]
	}
	if !changed {
		return text
	}

	var result strings.Builder
	result.Grow(outputLen)
	remaining = text
	for {
		newline := strings.IndexByte(remaining, '\n')
		line := remaining
		if newline >= 0 {
			line = remaining[:newline]
		}
		start := clipStart
		if len(line) <= start {
			start = 0
		}
		result.WriteString(line[start:min(clipEnd, len(line))])
		if newline < 0 {
			break
		}
		result.WriteByte('\n')
		remaining = remaining[newline+1:]
	}
	return result.String()
}
