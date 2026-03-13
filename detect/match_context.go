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
	ContextModeBytes             // offset-based (bytes before/after)
	ContextModeBox               // line + optional column based
)

// MatchContextSpec describes how much context to extract around a match.
type MatchContextSpec struct {
	Mode          ContextMode
	BytesBefore   int // bytes before match start (offset mode: context window; box mode: byte limit)
	BytesAfter    int // bytes after match end (offset mode: context window; box mode: byte limit)
	LinesBefore   int
	LinesAfter    int
	ColumnsBefore int
	ColumnsAfter  int
}

// IsZero returns true if no context extraction is configured.
func (m MatchContextSpec) IsZero() bool {
	return m.Mode == ContextModeNone
}

var tokenRe = regexp.MustCompile(`(?i)^([+-]?)(\d+)([BLC]?)$`)

// ParseMatchContext parses a match-context specification string.
//
// Syntax examples:
//
//	"100"        → 100 bytes before and after
//	"100B"       → 100 bytes before and after
//	"-128B,+16B" → 128 bytes before, 16 bytes after
//	"10L"        → 10 lines before and after
//	"-10L,+2L"   → 10 lines before, 2 lines after
//	"10L,500B"   → 10 lines, clipped to 500 bytes before/after match
//	"-2C,+10L,-2L,+4C" → box mode with column constraints
func ParseMatchContext(s string) (MatchContextSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return MatchContextSpec{}, nil
	}

	tokens := strings.Split(s, ",")

	type parsed struct {
		dir  string // "", "+", "-"
		val  int
		typ  string // "B", "L", "C" (uppercase)
	}

	var parts []parsed
	hasLineOrCol := false
	hasByte := false

	for _, tok := range tokens {
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
			typ = "B"
		}

		if typ == "L" || typ == "C" {
			hasLineOrCol = true
		}
		if typ == "B" {
			hasByte = true
		}

		parts = append(parts, parsed{dir: dir, val: val, typ: typ})
	}

	// Box mode if any L or C tokens exist. B in box mode = byte limit around match.
	if hasLineOrCol {
		spec := MatchContextSpec{Mode: ContextModeBox}

		// Track whether we've seen directed/undirected values per type
		var (
			bBefore, bAfter       int
			bBeforeSet, bAfterSet bool
			bUndirected           int
			bUndirectedSet        bool

			lBefore, lAfter       int
			lBeforeSet, lAfterSet bool
			lUndirected           int
			lUndirectedSet        bool

			cBefore, cAfter       int
			cBeforeSet, cAfterSet bool
			cUndirected           int
			cUndirectedSet        bool
		)

		for _, p := range parts {
			switch p.typ {
			case "B":
				switch p.dir {
				case "-":
					if p.val > bBefore {
						bBefore = p.val
					}
					bBeforeSet = true
				case "+":
					if p.val > bAfter {
						bAfter = p.val
					}
					bAfterSet = true
				default:
					if p.val > bUndirected {
						bUndirected = p.val
					}
					bUndirectedSet = true
				}
			case "L":
				// L values always include the match line, so subtract 1
				// to get the expansion count. "1L" = just the match line,
				// "-10L" = match line + 9 before, "+10L" = match line + 9 after.
				v := max(p.val-1, 0)
				switch p.dir {
				case "-":
					if v > lBefore {
						lBefore = v
					}
					lBeforeSet = true
				case "+":
					if v > lAfter {
						lAfter = v
					}
					lAfterSet = true
				default:
					if v > lUndirected {
						lUndirected = v
					}
					lUndirectedSet = true
				}
			case "C":
				switch p.dir {
				case "-":
					if p.val > cBefore {
						cBefore = p.val
					}
					cBeforeSet = true
				case "+":
					if p.val > cAfter {
						cAfter = p.val
					}
					cAfterSet = true
				default:
					if p.val > cUndirected {
						cUndirected = p.val
					}
					cUndirectedSet = true
				}
			}
		}

		// Resolve bytes (byte limit around match in box mode)
		spec.BytesBefore = resolveDirection(bBefore, bBeforeSet, bAfter, bAfterSet, bUndirected, bUndirectedSet, true)
		spec.BytesAfter = resolveDirection(bBefore, bBeforeSet, bAfter, bAfterSet, bUndirected, bUndirectedSet, false)

		// Resolve lines
		spec.LinesBefore = resolveDirection(lBefore, lBeforeSet, lAfter, lAfterSet, lUndirected, lUndirectedSet, true)
		spec.LinesAfter = resolveDirection(lBefore, lBeforeSet, lAfter, lAfterSet, lUndirected, lUndirectedSet, false)

		// Resolve columns
		spec.ColumnsBefore = resolveDirection(cBefore, cBeforeSet, cAfter, cAfterSet, cUndirected, cUndirectedSet, true)
		spec.ColumnsAfter = resolveDirection(cBefore, cBeforeSet, cAfter, cAfterSet, cUndirected, cUndirectedSet, false)

		return spec, nil
	}

	// Byte-only mode
	if hasByte {
		spec := MatchContextSpec{Mode: ContextModeBytes}

		var (
			bBefore, bAfter       int
			bBeforeSet, bAfterSet bool
			bUndirected           int
			bUndirectedSet        bool
		)

		for _, p := range parts {
			switch p.dir {
			case "-":
				if p.val > bBefore {
					bBefore = p.val
				}
				bBeforeSet = true
			case "+":
				if p.val > bAfter {
					bAfter = p.val
				}
				bAfterSet = true
			default:
				if p.val > bUndirected {
					bUndirected = p.val
				}
				bUndirectedSet = true
			}
		}

		spec.BytesBefore = resolveDirection(bBefore, bBeforeSet, bAfter, bAfterSet, bUndirected, bUndirectedSet, true)
		spec.BytesAfter = resolveDirection(bBefore, bBeforeSet, bAfter, bAfterSet, bUndirected, bUndirectedSet, false)

		return spec, nil
	}

	return MatchContextSpec{}, fmt.Errorf("invalid match-context spec %q", s)
}

// resolveDirection applies the resolution rules:
// - If only undirected is set, use it for both directions.
// - If a directional value and an undirected value coexist, the undirected fills the missing direction.
// - If a direction is repeated, the largest value wins.
// - If only the opposite direction is given, this direction defaults to 0.
func resolveDirection(before int, beforeSet bool, after int, afterSet bool, undirected int, undirectedSet bool, isBefore bool) int {
	if isBefore {
		if beforeSet {
			if undirectedSet && undirected > before {
				return undirected
			}
			return before
		}
		if undirectedSet {
			return undirected
		}
		return 0
	}
	// isAfter
	if afterSet {
		if undirectedSet && undirected > after {
			return undirected
		}
		return after
	}
	if undirectedSet {
		return undirected
	}
	return 0
}

// extractContext extracts context around the match from the fragment raw content.
// matchIndex is the [start, end) byte range of the match within raw.
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
	matchStart := matchIndex[0]
	matchEnd := matchIndex[1]

	// Find the start of the line containing matchStart
	lineStart := matchStart
	for lineStart > 0 && raw[lineStart-1] != '\n' {
		lineStart--
	}

	// Find the end of the line containing matchEnd
	lineEnd := matchEnd
	for lineEnd < len(raw) && raw[lineEnd] != '\n' {
		lineEnd++
	}

	// Expand backward by LinesBefore newlines
	contextStart := lineStart
	for i := 0; i < spec.LinesBefore && contextStart > 0; i++ {
		contextStart-- // skip past the \n
		for contextStart > 0 && raw[contextStart-1] != '\n' {
			contextStart--
		}
	}

	// Expand forward by LinesAfter newlines
	contextEnd := lineEnd
	for i := 0; i < spec.LinesAfter && contextEnd < len(raw); i++ {
		contextEnd++ // skip past the \n
		for contextEnd < len(raw) && raw[contextEnd] != '\n' {
			contextEnd++
		}
	}

	extracted := raw[contextStart:contextEnd]

	// Apply column constraints if set
	if spec.ColumnsBefore > 0 || spec.ColumnsAfter > 0 {
		// Compute match column position relative to its line
		matchCol := matchStart - lineStart
		matchLen := matchEnd - matchStart

		colStart := max(matchCol-spec.ColumnsBefore, 0)
		colEnd := matchCol + matchLen + spec.ColumnsAfter

		lines := strings.Split(extracted, "\n")
		for i, line := range lines {
			cs := min(colStart, len(line))
			ce := min(colEnd, len(line))
			lines[i] = line[cs:ce]
		}
		extracted = strings.Join(lines, "\n")
	}

	// Apply byte limits around the match position within the extracted text.
	// BytesBefore limits bytes before match start; BytesAfter limits bytes after match end.
	if spec.BytesBefore > 0 || spec.BytesAfter > 0 {
		// matchStart/matchEnd are positions in raw; translate to positions in extracted
		mStart := matchStart - contextStart
		mEnd := matchEnd - contextStart

		trimStart := 0
		if spec.BytesBefore > 0 {
			trimStart = max(mStart-spec.BytesBefore, 0)
		}

		trimEnd := len(extracted)
		if spec.BytesAfter > 0 {
			trimEnd = min(mEnd+spec.BytesAfter, len(extracted))
		}

		extracted = extracted[trimStart:trimEnd]
	}

	return extracted
}
