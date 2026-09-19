// Package regexspan derives conservative search windows around rule keywords.
// A plan is available only when every regex match must contain a keyword and
// the surrounding text has a provable byte or newline bound.
package regexspan

import (
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// Plan bounds text before and after a keyword. A negative After means the
// suffix has unbounded length but contains at most Newlines newline bytes.
type Plan struct {
	Before, After, Newlines int
	// RequiredByte is mandatory ASCII punctuation absent from the keywords.
	// Zero means no additional literal requirement was proven.
	RequiredByte byte
}

// Compile returns nil when narrowing could omit a match. Keywords remain an
// independent eligibility filter; they need not be literal regex prefixes.
func Compile(pattern string, keywords []string) *Plan {
	if len(keywords) == 0 {
		return nil
	}
	for _, keyword := range keywords {
		if keyword == "" {
			return nil
		}
		for _, r := range keyword {
			if r >= utf8.RuneSelf {
				return nil
			}
		}
	}
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	plan := analyze(re, keywords)
	if plan != nil {
		required := mandatoryPunctuation(re)
		for _, keyword := range keywords {
			for i := range keyword {
				required[keyword[i]] = false
			}
		}
		for b, needed := range required {
			if needed {
				plan.RequiredByte = byte(b)
				break
			}
		}
	}
	return plan
}

func analyze(re *syntax.Regexp, keywords []string) *Plan {
	if literals, ok := literalAlternatives(re); ok {
		combined := &Plan{}
		for _, literal := range literals {
			found := false
			for _, keyword := range keywords {
				keyword = strings.ToLower(keyword)
				if index := strings.Index(strings.ToLower(literal), keyword); index >= 0 {
					tail := literal[index+len(keyword):]
					combined.Before = max(combined.Before, index*utf8.UTFMax)
					combined.After = max(combined.After, len(tail)*utf8.UTFMax)
					combined.Newlines = max(combined.Newlines, strings.Count(tail, "\n"))
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}
		return combined
	}
	switch re.Op {
	case syntax.OpCapture:
		return analyze(re.Sub[0], keywords)
	case syntax.OpConcat:
		before := 0
		for i, sub := range re.Sub {
			end := i + 1
			plan := analyze(sub, keywords)
			// Captures can split a required keyword, e.g. (https?)://.
			// Join only finite literal siblings, preserving capture syntax.
			for plan == nil && end < len(re.Sub) {
				end++
				joined := &syntax.Regexp{Op: syntax.OpConcat, Sub: re.Sub[i:end]}
				if _, ok := literalAlternatives(joined); !ok {
					break
				}
				plan = analyze(joined, keywords)
			}
			if plan != nil {
				plan.Before = add(before, plan.Before)
				for _, suffix := range re.Sub[end:] {
					width := measure(suffix)
					plan.After = add(plan.After, width.bytes)
					plan.Newlines = add(plan.Newlines, width.lines)
				}
				if plan.Before >= 0 && (plan.After >= 0 || plan.Newlines >= 0) {
					return plan
				}
			}
			before = add(before, measure(sub).bytes)
			if before < 0 {
				break
			}
		}
	case syntax.OpAlternate:
		combined := &Plan{}
		for _, sub := range re.Sub {
			plan := analyze(sub, keywords)
			if plan == nil {
				return nil
			}
			combined.Before = widest(combined.Before, plan.Before)
			combined.After = widest(combined.After, plan.After)
			combined.Newlines = widest(combined.Newlines, plan.Newlines)
		}
		return combined
	}
	return nil
}

// syntax.Parse factors alternatives such as access|auth into a(?:ccess|uth).
// Expand only small, entirely literal subtrees to recover those anchors.
func literalAlternatives(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= utf8.RuneSelf {
				return nil, false
			}
		}
		return []string{string(re.Rune)}, true
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpCapture:
		return literalAlternatives(re.Sub[0])
	case syntax.OpQuest:
		values, ok := literalAlternatives(re.Sub[0])
		return append(values, ""), ok
	case syntax.OpCharClass:
		var values []string
		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i+1] >= utf8.RuneSelf || int(re.Rune[i+1]-re.Rune[i])+len(values) >= 16 {
				return nil, false
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				values = append(values, string(r))
			}
		}
		return values, true
	case syntax.OpConcat, syntax.OpAlternate:
		var values []string
		if re.Op == syntax.OpConcat {
			values = []string{""}
		}
		for _, sub := range re.Sub {
			next, ok := literalAlternatives(sub)
			if !ok {
				return nil, false
			}
			if re.Op == syntax.OpAlternate {
				values = append(values, next...)
			} else {
				if len(values)*len(next) > 64 {
					return nil, false
				}
				var joined []string
				for _, prefix := range values {
					for _, suffix := range next {
						if len(prefix)+len(suffix) > 256 {
							return nil, false
						}
						joined = append(joined, prefix+suffix)
					}
				}
				values = joined
			}
			if len(values) > 64 {
				return nil, false
			}
		}
		return values, true
	}
	return nil, false
}

type width struct{ bytes, lines int }

func measure(re *syntax.Regexp) width {
	switch re.Op {
	case syntax.OpLiteral:
		return width{len(re.Rune) * utf8.UTFMax, countNewlines(re.Rune)}
	case syntax.OpCharClass:
		lines := 0
		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i] <= '\n' && '\n' <= re.Rune[i+1] {
				lines = 1
			}
		}
		return width{utf8.UTFMax, lines}
	case syntax.OpAnyChar:
		return width{utf8.UTFMax, 1}
	case syntax.OpAnyCharNotNL:
		return width{utf8.UTFMax, 0}
	case syntax.OpCapture, syntax.OpQuest:
		return measure(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		w := measure(re.Sub[0])
		count := -1
		if re.Op == syntax.OpRepeat {
			count = re.Max
		}
		return width{multiply(w.bytes, count), multiply(w.lines, count)}
	case syntax.OpConcat:
		var total width
		for _, sub := range re.Sub {
			w := measure(sub)
			total.bytes = add(total.bytes, w.bytes)
			total.lines = add(total.lines, w.lines)
		}
		return total
	case syntax.OpAlternate:
		var total width
		for _, sub := range re.Sub {
			w := measure(sub)
			total.bytes = widest(total.bytes, w.bytes)
			total.lines = widest(total.lines, w.lines)
		}
		return total
	default:
		return width{}
	}
}

func countNewlines(runes []rune) int {
	count := 0
	for _, r := range runes {
		if r == '\n' {
			count++
		}
	}
	return count
}

// Saturation also bounds work on adversarial nested repetitions.
const limit = 1 << 20

func add(a, b int) int {
	if a < 0 || b < 0 || a > limit-b {
		return -1
	}
	return a + b
}

func multiply(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a < 0 || b < 0 || a > limit/b {
		return -1
	}
	return a * b
}

func widest(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return max(a, b)
}

type Span struct{ Start, End int }

const maxWindows = 256

// Windows accumulates merged ranges for one rule and one input. Keyword
// callbacks must be ordered by their end offsets, as in Aho-Corasick traversal.
type Windows struct {
	Spans []Span
	// Cache newline searches across keywords on the same line. Without this,
	// dense keywords in a long minified line would cause quadratic rescanning.
	firstNewline, lastNewline int
}

func (w *Windows) Add(text string, start, end int, plan *Plan) {
	if len(w.Spans) == 1 && w.Spans[0].Start == 0 && w.Spans[0].End == len(text) {
		return
	}
	start = max(0, start-plan.Before-utf8.UTFMax)
	if plan.After >= 0 {
		end = min(len(text), end+plan.After+utf8.UTFMax)
	} else {
		if end > w.firstNewline || len(w.Spans) == 0 {
			first := strings.IndexByte(text[end:], '\n')
			w.firstNewline, w.lastNewline = len(text), len(text)
			if first >= 0 {
				w.firstNewline = end + first
				w.lastNewline = w.firstNewline
				for range plan.Newlines {
					next := strings.IndexByte(text[w.lastNewline+1:], '\n')
					if next < 0 {
						w.lastNewline = len(text)
						break
					}
					w.lastNewline += next + 1
				}
			}
		}
		end = min(len(text), w.lastNewline+1+utf8.UTFMax)
	}
	// Padding preserves empty-width assertions and avoids introducing UTF-8
	// decoding boundaries that were not present in the original input.
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	for len(w.Spans) > 0 {
		last := w.Spans[len(w.Spans)-1]
		if last.End < start {
			break
		}
		start, end = min(start, last.Start), max(end, last.End)
		w.Spans = w.Spans[:len(w.Spans)-1]
	}
	w.Spans = append(w.Spans, Span{start, end})
	// Bound retained scratch for arbitrarily large SDK fragments.
	if len(w.Spans) > maxWindows {
		w.Spans = w.Spans[:1]
		w.Spans[0] = Span{0, len(text)}
	}
}

func (w *Windows) Reset() {
	w.Spans = w.Spans[:0]
	w.firstNewline, w.lastNewline = 0, 0
}

// mandatoryPunctuation intersects alternatives and ignores optional syntax.
// Only ASCII punctuation is selected, so Unicode case folding cannot change it.
func mandatoryPunctuation(re *syntax.Regexp) (required [128]bool) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= '!' && r <= '~' && !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
				required[r] = true
			}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return mandatoryPunctuation(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return mandatoryPunctuation(re.Sub[0])
		}
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			next := mandatoryPunctuation(sub)
			for b := range required {
				required[b] = required[b] || next[b]
			}
		}
	case syntax.OpAlternate:
		if len(re.Sub) > 0 {
			required = mandatoryPunctuation(re.Sub[0])
			for _, sub := range re.Sub[1:] {
				next := mandatoryPunctuation(sub)
				for b := range required {
					required[b] = required[b] && next[b]
				}
			}
		}
	}
	return required
}
