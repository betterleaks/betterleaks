package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ContextMode determines how match context is extracted.
type ContextMode int

const (
	ContextModeNone  ContextMode = iota
	ContextModeBytes             // B: offset-based (bytes before/after)
	ContextModeBox               // L/C: line-based (L) with optional column window (C)
)

// MatchContextSpec describes how much context to extract around a match.
type MatchContextSpec struct {
	Mode        ContextMode
	BytesBefore int // For B
	BytesAfter  int // For B
	LinesBefore int // For L
	LinesAfter  int // For L
	ColsBefore  int // For C
	ColsAfter   int // For C
}

// IsZero returns true if no context extraction is configured.
func (m MatchContextSpec) IsZero() bool {
	return m.Mode == ContextModeNone
}

// Matches numbers with an optional sign and an optional L, C, or B suffix.
var tokenRe = regexp.MustCompile(`(?i)^([+-]?)(\d+)([LCB]?)$`)

// ParseMatchContext parses a match-context specification string.
func ParseMatchContext(s string) (MatchContextSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return MatchContextSpec{}, nil
	}

	var b, l, c struct{ before, after, any int }
	hasB, hasL, hasC := false, false, false

	for tok := range strings.SplitSeq(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return MatchContextSpec{}, fmt.Errorf("empty token in match-context spec %q", s)
		}

		m := tokenRe.FindStringSubmatch(tok)
		if m == nil {
			return MatchContextSpec{}, fmt.Errorf("invalid match-context token %q", tok)
		}

		dir := m[1]
		val, _ := strconv.Atoi(m[2])
		typ := strings.ToUpper(m[3])
		if typ == "" {
			typ = "B" // Default to bytes if no unit is specified
		}

		switch typ {
		case "L":
			hasL = true
			val = max(val-1, 0) // L includes match line, subtract 1 for expansion count
			if dir == "-" {
				l.before = max(l.before, val)
			} else if dir == "+" {
				l.after = max(l.after, val)
			} else {
				l.any = max(l.any, val)
			}
		case "C":
			hasC = true
			if dir == "-" {
				c.before = max(c.before, val)
			} else if dir == "+" {
				c.after = max(c.after, val)
			} else {
				c.any = max(c.any, val)
			}
		case "B":
			hasB = true
			if dir == "-" {
				b.before = max(b.before, val)
			} else if dir == "+" {
				b.after = max(b.after, val)
			} else {
				b.any = max(b.any, val)
			}
		}
	}

	// Prevent mixing incompatible modes
	if hasB && (hasL || hasC) {
		return MatchContextSpec{}, fmt.Errorf("cannot mix bytes (B) with lines/columns (L/C) in spec %q", s)
	}

	spec := MatchContextSpec{}

	if hasL || hasC {
		spec.Mode = ContextModeBox
		spec.LinesBefore = max(l.before, l.any)
		spec.LinesAfter = max(l.after, l.any)
		spec.ColsBefore = max(c.before, c.any)
		spec.ColsAfter = max(c.after, c.any)
	} else if hasB {
		spec.Mode = ContextModeBytes
		spec.BytesBefore = max(b.before, b.any)
		spec.BytesAfter = max(b.after, b.any)
	} else {
		return MatchContextSpec{}, fmt.Errorf("invalid match-context spec %q", s)
	}

	return spec, nil
}

// extractContext extracts context around the match from the fragment raw content.
func extractContext(raw string, matchIndex []int, spec MatchContextSpec) string {
	if spec.IsZero() || len(raw) == 0 {
		return ""
	}

	switch spec.Mode {
	case ContextModeBytes:
		return extractBytesContext(raw, matchIndex, spec)
	case ContextModeBox:
		return extractBoxContext(raw, matchIndex, spec)
	default:
		return ""
	}
}

func extractBytesContext(raw string, matchIndex []int, spec MatchContextSpec) string {
	start := max(matchIndex[0]-spec.BytesBefore, 0)
	end := min(matchIndex[1]+spec.BytesAfter, len(raw))
	return raw[start:end]
}

func extractBoxContext(raw string, matchIndex []int, spec MatchContextSpec) string {
	matchStart, matchEnd := matchIndex[0], matchIndex[1]

	// Find the start of the line containing matchStart
	lineStart := strings.LastIndexByte(raw[:matchStart], '\n') + 1

	// Find the end of the line containing matchEnd
	lineEnd := strings.IndexByte(raw[matchEnd:], '\n')
	if lineEnd == -1 {
		lineEnd = len(raw)
	} else {
		lineEnd += matchEnd // adjust for slice offset
	}

	// Expand backward by LinesBefore
	ctxStart := lineStart
	for i := 0; i < spec.LinesBefore && ctxStart > 0; i++ {
		ctxStart = strings.LastIndexByte(raw[:ctxStart-1], '\n') + 1
	}

	// Expand forward by LinesAfter
	ctxEnd := lineEnd
	for i := 0; i < spec.LinesAfter && ctxEnd < len(raw); i++ {
		nextNL := strings.IndexByte(raw[ctxEnd+1:], '\n')
		if nextNL == -1 {
			ctxEnd = len(raw)
			break
		}
		ctxEnd += nextNL + 1
	}

	extracted := raw[ctxStart:ctxEnd]

	// Box mode: apply column clipping to each line around the match column
	if spec.ColsBefore > 0 || spec.ColsAfter > 0 {
		matchCol := matchStart - lineStart
		matchLen := matchEnd - matchStart
		clipStart := max(matchCol-spec.ColsBefore, 0)
		clipEnd := matchCol + matchLen + spec.ColsAfter

		lines := strings.Split(extracted, "\n")
		for i, line := range lines {
			cs := min(clipStart, len(line))
			ce := min(clipEnd, len(line))
			lines[i] = line[cs:ce]
		}
		extracted = strings.Join(lines, "\n")
	}

	return extracted
}
