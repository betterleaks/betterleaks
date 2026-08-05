package detect

import (
	"strings"

	"github.com/betterleaks/betterleaks/internal/contextwindow"
)

// ContextMode determines how match context is extracted.
type ContextMode = contextwindow.Mode

const (
	ContextModeNone = contextwindow.ModeNone
	ContextModeCols = contextwindow.ModeCols // offset-based (characters/columns before/after)
	ContextModeBox  = contextwindow.ModeBox  // line-based; optional C clips each line to a column window around the match
)

// MatchContextSpec describes how much context to extract around a match.
type MatchContextSpec = contextwindow.Spec

// ParseMatchContext parses a match-context specification string.
func ParseMatchContext(s string) (MatchContextSpec, error) {
	return contextwindow.Parse(s)
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
