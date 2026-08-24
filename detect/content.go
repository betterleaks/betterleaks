package detect

import (
	"bytes"
	"strings"

	"github.com/betterleaks/betterleaks/detect/codec"
	"github.com/betterleaks/betterleaks/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/internal/contextwindow"
	blregexp "github.com/betterleaks/betterleaks/regexp"
)

// scanContent keeps exactly one canonical representation of a fragment or
// decode pass. String-backed content is retained for compatibility callers;
// source scans use data so their pooled read buffer does not need to be copied
// into an immutable string before detection starts.
type scanContent struct {
	text       string
	data       []byte
	byteBacked bool
}

func stringScanContent(text string) scanContent {
	return scanContent{text: text}
}

func byteScanContent(data []byte) scanContent {
	return scanContent{data: data, byteBacked: true}
}

func (c *scanContent) len() int {
	if c.byteBacked {
		return len(c.data)
	}
	return len(c.text)
}

func (c *scanContent) visit(matcher *ahocorasick.Matcher, yield func(patternID, end int) bool) {
	if c.byteBacked {
		matcher.VisitEndsBytes(c.data, yield)
		return
	}
	matcher.VisitEnds(c.text, yield)
}

func (c *scanContent) findAllIndex(re *blregexp.Regexp) [][]int {
	if c.byteBacked {
		return re.FindAllIndex(c.data, -1)
	}
	return re.FindAllStringIndex(c.text, -1)
}

func (c *scanContent) findAllIndexSpan(re *blregexp.Regexp, window matchSpanWindow) [][]int {
	if !window.active {
		return c.findAllIndex(re)
	}
	return c.findAllIndexRange(re, window.span.start, window.span.end)
}

func (c *scanContent) findAllIndexRange(re *blregexp.Regexp, start, end int) [][]int {
	start, end = clampRange(start, end, c.len())
	if start == 0 && end == c.len() {
		return c.findAllIndex(re)
	}

	var matches [][]int
	if c.byteBacked {
		matches = re.FindAllIndex(c.data[start:end], -1)
	} else {
		matches = re.FindAllStringIndex(c.text[start:end], -1)
	}

	accepted := matches[:0]
	for _, match := range matches {
		match[0] += start
		match[1] += start
		// Slicing can create artificial text, line, or word boundaries. The
		// analyzer reserves one maximum-width UTF-8 rune on each side. A real
		// match anchored by the keyword cannot consume that guard, so matches
		// that do are slice-boundary artifacts.
		if start > 0 && match[0] < start+matchSpanBoundaryPadding {
			continue
		}
		if end < c.len() && match[1] > end-matchSpanBoundaryPadding {
			continue
		}
		accepted = append(accepted, match)
	}
	return accepted
}

func (c *scanContent) submatchIndex(re *blregexp.Regexp, start, end int) []int {
	start, end = clampRange(start, end, c.len())
	if c.byteBacked {
		return re.FindSubmatchIndex(c.data[start:end])
	}
	return re.FindStringSubmatchIndex(c.text[start:end])
}

func (c *scanContent) sliceString(start, end int) string {
	start, end = clampRange(start, end, c.len())
	if c.byteBacked {
		return string(c.data[start:end])
	}
	return c.text[start:end]
}

func (c *scanContent) trimmedMatch(start, end int) string {
	start, end = clampRange(start, end, c.len())
	if c.byteBacked {
		return string(bytes.Trim(c.data[start:end], "\n"))
	}
	return strings.Trim(c.text[start:end], "\n")
}

func (c *scanContent) contains(start, end int, value string) bool {
	start, end = clampRange(start, end, c.len())
	if c.byteBacked {
		return bytes.Contains(c.data[start:end], []byte(value))
	}
	return strings.Contains(c.text[start:end], value)
}

func (c *scanContent) fullText() string {
	if c.byteBacked {
		return string(c.data)
	}
	return c.text
}

func (c *scanContent) lastIndexAnyBefore(end int, chars string) int {
	end = min(max(end, 0), c.len())
	if c.byteBacked {
		return bytes.LastIndexAny(c.data[:end], chars)
	}
	return strings.LastIndexAny(c.text[:end], chars)
}

func (c *scanContent) indexAnyAfter(start int, chars string) int {
	start = min(max(start, 0), c.len())
	if c.byteBacked {
		return bytes.IndexAny(c.data[start:], chars)
	}
	return strings.IndexAny(c.text[start:], chars)
}

func (c *scanContent) lineOffsets() *lineOffsetBuffer {
	if c.byteBacked {
		return getLineOffsetsBytes(c.data)
	}
	return getLineOffsets(c.text)
}

func (c *scanContent) rawLineStarts() []int {
	starts := make([]int, 1, max(1, c.len()/128))
	if c.byteBacked {
		return appendLineOffsetsBytes(starts, c.data)
	}
	return appendLineOffsets(starts, c.text)
}

func (c *scanContent) extractContext(matchIndex []int, spec contextwindow.Spec) string {
	if c.byteBacked {
		return string(contextwindow.ExtractBytes(c.data, matchIndex, spec))
	}
	return contextwindow.Extract(c.text, matchIndex, spec)
}

func (c *scanContent) currentLine(segments []*codec.EncodedSegment) string {
	if c.byteBacked {
		return string(codec.CurrentLineBytes(segments, c.data))
	}
	return codec.CurrentLine(segments, c.text)
}

func (c *scanContent) decode(decoder *codec.Decoder, predecessors []*codec.EncodedSegment) (scanContent, []*codec.EncodedSegment) {
	if c.byteBacked {
		decoded, segments := decoder.DecodeBytes(c.data, predecessors)
		return byteScanContent(decoded), segments
	}
	decoded, segments := decoder.Decode(c.text, predecessors)
	return stringScanContent(decoded), segments
}

// matchSurroundings returns the current line with the match removed plus a
// bounded number of neighboring lines, and the prefix of the current line.
// Removing the match prevents password-key text from satisfying the context
// checks intended to find independent authentication evidence.
func (c *scanContent) matchSurroundings(matchStart, matchEnd, maxBytes, lines int) (string, string) {
	matchStart, matchEnd = clampRange(matchStart, matchEnd, c.len())
	lineStart := c.lastIndexAnyBefore(matchStart, "\n") + 1
	lineEnd := c.len()
	if next := c.indexAnyAfter(matchEnd, "\n"); next >= 0 {
		lineEnd = matchEnd + next
	}

	contextStart := lineStart
	for range lines {
		if contextStart == 0 {
			break
		}
		contextStart = c.lastIndexAnyBefore(contextStart-1, "\n") + 1
	}
	contextEnd := lineEnd
	for range lines {
		if contextEnd >= c.len() {
			break
		}
		next := c.indexAnyAfter(contextEnd+1, "\n")
		if next < 0 {
			contextEnd = c.len()
			break
		}
		contextEnd += next + 1
	}
	contextStart = max(contextStart, matchStart-maxBytes)
	contextEnd = min(contextEnd, matchEnd+maxBytes)

	linePrefix := c.sliceString(lineStart, matchStart)
	left := c.sliceString(contextStart, matchStart)
	right := c.sliceString(matchEnd, contextEnd)
	// Preserve the generic-password filter's original split/join behavior: the
	// removed match is represented by a separator even when its suffix already
	// begins with a newline.
	return left + "\n" + right, linePrefix
}

func clampRange(start, end, length int) (int, int) {
	start = min(max(start, 0), length)
	end = min(max(end, start), length)
	return start, end
}
