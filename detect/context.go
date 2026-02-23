package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MatchContext holds the parsed --match-context configuration.
type MatchContext struct {
	Lines int // number of lines before/after the match
	Chars int // max characters per context line (0 = unlimited)
}

// IsSet returns true if context extraction is configured.
func (c MatchContext) IsSet() bool {
	return c.Lines > 0
}

// contextSpecRe matches "5", "5L", "5L250C"
var contextSpecRe = regexp.MustCompile(`^(\d+)L?(?:(\d+)C)?$`)

// ParseMatchContext parses a --match-context spec string.
// Accepted formats: "5", "5L", "5L250C".
func ParseMatchContext(spec string) (MatchContext, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return MatchContext{}, nil
	}

	m := contextSpecRe.FindStringSubmatch(spec)
	if m == nil {
		return MatchContext{}, fmt.Errorf("invalid match-context spec: %q (expected format: 5, 5L, or 5L250C)", spec)
	}

	lines, err := strconv.Atoi(m[1])
	if err != nil {
		return MatchContext{}, fmt.Errorf("invalid lines value in match-context spec: %w", err)
	}
	if lines < 0 {
		return MatchContext{}, fmt.Errorf("lines must be non-negative in match-context spec")
	}

	var chars int
	if m[2] != "" {
		chars, err = strconv.Atoi(m[2])
		if err != nil {
			return MatchContext{}, fmt.Errorf("invalid chars value in match-context spec: %w", err)
		}
		if chars < 0 {
			return MatchContext{}, fmt.Errorf("chars must be non-negative in match-context spec")
		}
	}

	return MatchContext{Lines: lines, Chars: chars}, nil
}

// extractContext extracts surrounding lines (including the match line(s)) from
// the fragment raw content as a single string.
//
// newlineIndices is the slice returned by findNewlineIndices(raw).
// loc is the Location computed for the match.
// cfg controls how many lines and characters to include.
func extractContext(raw string, newlineIndices [][]int, loc Location, cfg MatchContext) string {
	if !cfg.IsSet() || len(raw) == 0 {
		return ""
	}

	// Build a list of line start positions from newlineIndices.
	// Each "line" starts right after the previous newline (or at 0 for the first line).
	// lineStarts[i] is the byte offset where line i begins.
	// lineEnds[i] is the byte offset where line i ends (exclusive, at the \n or end of raw).
	numNewlines := len(newlineIndices)
	// Total lines = number of newlines + 1 (the last line may not end with \n)
	totalLines := numNewlines + 1

	lineStarts := make([]int, totalLines)
	lineEnds := make([]int, totalLines)

	for i := 0; i < numNewlines; i++ {
		lineEnds[i] = newlineIndices[i][0]
		if i+1 < totalLines {
			lineStarts[i+1] = newlineIndices[i][0] + 1
		}
	}
	// First line always starts at 0
	lineStarts[0] = 0
	// Last line ends at end of raw
	lineEnds[totalLines-1] = len(raw)

	// Determine the range of lines to include.
	firstLine := loc.startLine - cfg.Lines
	if firstLine < 0 {
		firstLine = 0
	}
	lastLine := loc.endLine + cfg.Lines
	if lastLine >= totalLines {
		lastLine = totalLines - 1
	}

	// Extract the context substring.
	contextStart := lineStarts[firstLine]
	contextEnd := lineEnds[lastLine]

	if contextStart > len(raw) {
		contextStart = len(raw)
	}
	if contextEnd > len(raw) {
		contextEnd = len(raw)
	}

	context := raw[contextStart:contextEnd]

	// Apply character truncation if configured.
	if cfg.Chars > 0 {
		context = truncateContextLines(context, cfg.Chars)
	}

	return context
}

// truncateContextLines truncates each line in the context to at most maxChars characters.
func truncateContextLines(context string, maxChars int) string {
	lines := strings.Split(context, "\n")
	for i, line := range lines {
		if len(line) > maxChars {
			lines[i] = line[:maxChars]
		}
	}
	return strings.Join(lines, "\n")
}
