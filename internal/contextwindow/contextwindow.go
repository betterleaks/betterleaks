// Package contextwindow parses directional line and character window specifications.
package contextwindow

import (
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

		lines := strings.Split(extracted, "\n")
		for i, line := range lines {
			lineStart := clipStart
			if len(line) <= lineStart {
				lineStart = 0
			}
			lines[i] = line[lineStart:min(clipEnd, len(line))]
		}
		extracted = strings.Join(lines, "\n")
	}

	return extracted
}
