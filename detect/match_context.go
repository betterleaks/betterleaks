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
	ContextModeNone ContextMode = iota
	ContextModeCols             // offset-based (characters/columns before/after)
	ContextModeBox              // line-based; optional C clips each line to a column window around the match
)

// MatchContextSpec describes how much context to extract around a match.
type MatchContextSpec struct {
	Mode        ContextMode
	ColsBefore  int // cols mode: context window; box mode: per-line column clip before match
	ColsAfter   int // cols mode: context window; box mode: per-line column clip after match
	LinesBefore int
	LinesAfter  int
}

// IsZero returns true if no context extraction is configured.
func (m MatchContextSpec) IsZero() bool {
	return m.Mode == ContextModeNone
}

type contextDirection struct {
	before     int
	after      int
	bidirected int
}

var tokenRe = regexp.MustCompile(`(?i)^([+-]?)(\d+)([CL]?)$`)

// ParseMatchContext parses a match-context specification string.
func ParseMatchContext(s string) (MatchContextSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return MatchContextSpec{}, nil
	}

	var c, l contextDirection
	hasL, hasC := false, false

	for tok := range strings.SplitSeq(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return MatchContextSpec{}, fmt.Errorf("empty token in match-context spec %q", s)
		}

		m := tokenRe.FindStringSubmatch(tok)
		if m == nil {
			return MatchContextSpec{}, fmt.Errorf("invalid match-context token %q", tok)
		}

		direction := m[1]
		val, _ := strconv.Atoi(m[2])
		typ := strings.ToUpper(m[3])
		if typ == "" {
			typ = "C" // Default to Cols
		}

		if typ == "L" {
			hasL = true
			val = max(val-1, 0) // L includes match line, subtract 1 for expansion count
			if direction == "-" {
				l.before = max(l.before, val)
			} else if direction == "+" {
				l.after = max(l.after, val)
			} else {
				l.bidirected = max(l.bidirected, val)
			}
		} else {
			hasC = true
			if direction == "-" {
				c.before = max(c.before, val)
			} else if direction == "+" {
				c.after = max(c.after, val)
			} else {
				c.bidirected = max(c.bidirected, val)
			}
		}
	}

	// Because all values are >= 0, resolution is simply max(directed, undirected)
	spec := MatchContextSpec{
		ColsBefore: max(c.before, c.bidirected),
		ColsAfter:  max(c.after, c.bidirected),
	}

	if hasL {
		spec.Mode = ContextModeBox
		spec.LinesBefore = max(l.before, l.bidirected)
		spec.LinesAfter = max(l.after, l.bidirected)
	} else if hasC {
		spec.Mode = ContextModeCols
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
	case ContextModeCols:
		return extractColsContext(raw, matchIndex, spec)
	case ContextModeBox:
		return extractBoxContext(raw, matchIndex, spec)
	default:
		return ""
	}
}

func extractColsContext(raw string, matchIndex []int, spec MatchContextSpec) string {
	start := max(matchIndex[0]-spec.ColsBefore, 0)
	end := min(matchIndex[1]+spec.ColsAfter, len(raw))
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

	// Box mode: apply column clipping to each line around the match column.
	// Column clipping only makes sense for single-line matches; when the match
	// spans multiple lines the first-line column offset is meaningless for
	// subsequent lines, so we skip clipping entirely.
	multiLine := strings.ContainsRune(raw[matchStart:matchEnd], '\n')
	if !multiLine && (spec.ColsBefore > 0 || spec.ColsAfter > 0) {
		matchCol := matchStart - lineStart
		matchLen := matchEnd - matchStart
		clipStart := max(matchCol-spec.ColsBefore, 0)
		clipEnd := matchCol + matchLen + spec.ColsAfter

		lines := strings.Split(extracted, "\n")
		for i, line := range lines {
			cs := clipStart
			if len(line) <= cs {
				cs = 0 // short line: show full content rather than nothing
			}
			ce := min(clipEnd, len(line))
			lines[i] = line[cs:ce]
		}
		extracted = strings.Join(lines, "\n")
	}

	return extracted
}
