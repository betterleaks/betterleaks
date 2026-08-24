package detect

import (
	"math"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/ahocorasick"
)

const (
	// Padding prevents a sliced regex from accepting anchors or word boundaries
	// created by the slice itself. Four bytes cover one maximum-width UTF-8 rune.
	matchSpanBoundaryPadding = utf8.UTFMax

	// Bounds this large save little on the source's 100 KB fragments. Treating
	// them as unbounded keeps the proof conservative and its arithmetic small.
	maxMatchSpanBytes = 64 * 1024

	// Literal expansion is deliberately finite. Exceeding any cap disables span
	// matching for that rule rather than risking construction-time blowups.
	maxLiteralVariants      = 32
	maxLiteralVariantBytes  = 256
	maxEnumeratedClassRunes = 256
)

// matchSpanPlan bounds a complete regex match around the end of a specific
// configured keyword. beforeBytes includes the keyword itself.
type matchSpanPlan struct {
	beforeBytes   int
	afterBytes    int
	beforeBounded bool
	afterBounded  bool
	valid         bool
}

type ruleMatchSpanPlan struct {
	keywords map[string]matchSpanPlan
}

type matchSpan struct {
	start int
	end   int
}

type ruleMatchSpanState struct {
	span     matchSpan
	epoch    uint32
	active   bool
	fullScan bool
}

type matchSpanWindow struct {
	span   matchSpan
	active bool
}

func (c *ruleCandidates) resetMatchSpans() {
	c.matchSpanEpoch++
	if c.matchSpanEpoch == 0 {
		// A stale state can share epoch zero after uint32 wraparound. This runs
		// at most once per four billion scan/decode passes.
		clear(c.matchSpanStates)
	}
}

func (c *ruleCandidates) addMatchSpan(ruleIndex, keywordEnd, contentLen int, plan matchSpanPlan) {
	state := &c.matchSpanStates[ruleIndex]
	if state.epoch != c.matchSpanEpoch {
		*state = ruleMatchSpanState{epoch: c.matchSpanEpoch}
	}
	if state.fullScan {
		return
	}

	start := 0
	if plan.beforeBounded {
		beforeBytes := plan.beforeBytes + matchSpanBoundaryPadding
		if keywordEnd > beforeBytes {
			start = keywordEnd - beforeBytes
		}
	}
	end := contentLen
	if plan.afterBounded {
		afterBytes := plan.afterBytes + matchSpanBoundaryPadding
		if afterBytes < contentLen-keywordEnd {
			end = keywordEnd + afterBytes
		}
	}

	span := matchSpan{start: start, end: end}
	if !state.active {
		state.span = span
		state.active = true
		if span.start == 0 && span.end == contentLen {
			state.fullScan = true
		}
		return
	}

	state.span.start = min(state.span.start, span.start)
	state.span.end = max(state.span.end, span.end)
	if state.span.start == 0 && state.span.end == contentLen {
		state.fullScan = true
	}
}

func (c *ruleCandidates) matchSpanWindow(ruleIndex int) matchSpanWindow {
	state := c.matchSpanStates[ruleIndex]
	if state.epoch != c.matchSpanEpoch || !state.active || state.fullScan {
		return matchSpanWindow{}
	}
	return matchSpanWindow{span: state.span, active: true}
}

func (c *ruleCandidates) hasMatchSpan(ruleIndex int) bool {
	state := c.matchSpanStates[ruleIndex]
	return state.epoch == c.matchSpanEpoch && state.active
}

// analyzeRuleMatchSpans proves that every accepted match contains an Aho-
// Corasick keyword and computes conservative byte bounds around each one. Any
// unsupported or ambiguous construct returns false and keeps the full scan.
func analyzeRuleMatchSpans(rule config.Rule) (ruleMatchSpanPlan, bool) {
	if rule.Regex == nil || len(rule.Keywords) == 0 {
		return ruleMatchSpanPlan{}, false
	}

	parsed, err := syntax.Parse(rule.Regex.String(), syntax.Perl)
	if err != nil {
		return ruleMatchSpanPlan{}, false
	}
	keywords := normalizeMatchSpanKeywords(rule.Keywords)
	if !guaranteesKeyword(parsed, keywords) {
		return ruleMatchSpanPlan{}, false
	}
	plans := make(map[string]matchSpanPlan, len(keywords))
	collectKeywordMatchSpans(parsed, keywords, boundedByteWidth(0), boundedByteWidth(0), plans)
	if len(plans) == 0 {
		return ruleMatchSpanPlan{}, false
	}
	return ruleMatchSpanPlan{keywords: plans}, true
}

func normalizeMatchSpanKeywords(keywords []string) []string {
	normalized := keywords
	copied := false
	for i, keyword := range keywords {
		lower := strings.ToLower(keyword)
		if lower == keyword {
			continue
		}
		if !copied {
			normalized = slices.Clone(keywords)
			copied = true
		}
		normalized[i] = lower
	}
	return normalized
}

type byteWidth struct {
	bytes   int
	bounded bool
}

func boundedByteWidth(bytes int) byteWidth {
	return byteWidth{bytes: bytes, bounded: true}
}

func addByteWidths(left, right byteWidth) byteWidth {
	if !left.bounded || !right.bounded || left.bytes > math.MaxInt-right.bytes {
		return byteWidth{}
	}
	return boundedByteWidth(left.bytes + right.bytes)
}

func repeatByteWidth(width byteWidth, count int) byteWidth {
	if count == 0 {
		return boundedByteWidth(0)
	}
	if count < 0 || !width.bounded || width.bytes > math.MaxInt/count {
		return byteWidth{}
	}
	return boundedByteWidth(width.bytes * count)
}

func limitedByteWidth(width byteWidth) byteWidth {
	if !width.bounded || width.bytes > maxMatchSpanBytes {
		return byteWidth{}
	}
	return width
}

// collectKeywordMatchSpans records directional bounds around every configured
// keyword that occurs as a regex literal. An unbounded side remains open to the
// fragment edge; a finite side can still avoid scanning unrelated content.
func collectKeywordMatchSpans(re *syntax.Regexp, keywords []string, prefix, suffix byteWidth, plans map[string]matchSpanPlan) {
	switch re.Op {
	case syntax.OpLiteral:
		literal := asciiLowerLiteral(re.Rune)
		if literal == "" {
			return
		}
		widths := make([]int, len(re.Rune)+1)
		for i, r := range re.Rune {
			width := utf8.RuneLen(r)
			if re.Flags&syntax.FoldCase != 0 {
				width = foldedRuneMaxBytes(r)
			}
			widths[i+1] = widths[i] + width
		}
		for _, keyword := range keywords {
			if keyword == "" || !isASCIIString(keyword) {
				continue
			}
			for searchFrom := 0; searchFrom <= len(literal)-len(keyword); {
				offset := strings.Index(literal[searchFrom:], keyword)
				if offset < 0 {
					break
				}
				start := searchFrom + offset
				end := start + len(keyword)
				before := limitedByteWidth(addByteWidths(prefix, boundedByteWidth(widths[end])))
				after := limitedByteWidth(addByteWidths(suffix, boundedByteWidth(widths[len(re.Rune)]-widths[end])))
				mergeKeywordMatchSpan(plans, keyword, before, after)
				searchFrom = start + 1
			}
		}
	case syntax.OpCapture, syntax.OpQuest:
		collectKeywordMatchSpans(re.Sub[0], keywords, prefix, suffix, plans)
	case syntax.OpConcat:
		after := make([]byteWidth, len(re.Sub)+1)
		after[len(re.Sub)] = boundedByteWidth(0)
		for i := len(re.Sub) - 1; i >= 0; i-- {
			after[i] = addByteWidths(regexByteWidth(re.Sub[i]), after[i+1])
		}
		before := boundedByteWidth(0)
		var run []literalVariant
		var runPrefix byteWidth
		for i, sub := range re.Sub {
			if subVariants, ok := regexLiteralVariants(sub); ok {
				if len(run) == 0 {
					run = []literalVariant{{}}
					runPrefix = addByteWidths(prefix, before)
				}
				combined, combinedOK := concatLiteralVariants(run, subVariants)
				if !combinedOK {
					run = []literalVariant{{}}
					runPrefix = addByteWidths(prefix, before)
					combined, combinedOK = concatLiteralVariants(run, subVariants)
				}
				if combinedOK {
					run = combined
					collectLiteralVariantMatchSpans(run, keywords, runPrefix, addByteWidths(suffix, after[i+1]), plans)
				} else {
					run = nil
				}
			} else {
				run = nil
			}
			collectKeywordMatchSpans(sub, keywords, addByteWidths(prefix, before), addByteWidths(suffix, after[i+1]), plans)
			before = addByteWidths(before, regexByteWidth(sub))
		}
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			collectKeywordMatchSpans(sub, keywords, prefix, suffix, plans)
		}
	case syntax.OpRepeat:
		width := regexByteWidth(re.Sub[0])
		extra := byteWidth{}
		if re.Max >= 0 {
			extra = repeatByteWidth(width, max(re.Max-1, 0))
		} else if width.bounded && width.bytes == 0 {
			extra = boundedByteWidth(0)
		}
		collectKeywordMatchSpans(re.Sub[0], keywords, addByteWidths(prefix, extra), addByteWidths(suffix, extra), plans)
	case syntax.OpStar, syntax.OpPlus:
		extra := byteWidth{}
		if width := regexByteWidth(re.Sub[0]); width.bounded && width.bytes == 0 {
			extra = boundedByteWidth(0)
		}
		collectKeywordMatchSpans(re.Sub[0], keywords, addByteWidths(prefix, extra), addByteWidths(suffix, extra), plans)
	}
}

func mergeKeywordMatchSpan(plans map[string]matchSpanPlan, keyword string, before, after byteWidth) {
	plan := plans[keyword]
	if !plan.valid {
		plan.beforeBounded = before.bounded
		plan.afterBounded = after.bounded
		plan.beforeBytes = before.bytes
		plan.afterBytes = after.bytes
		plan.valid = true
		plans[keyword] = plan
		return
	}
	if !before.bounded {
		plan.beforeBounded = false
		plan.beforeBytes = 0
	} else if plan.beforeBounded {
		plan.beforeBytes = max(plan.beforeBytes, before.bytes)
	}
	if !after.bounded {
		plan.afterBounded = false
		plan.afterBytes = 0
	} else if plan.afterBounded {
		plan.afterBytes = max(plan.afterBytes, after.bytes)
	}
	plans[keyword] = plan
}

type literalVariant struct {
	text   string
	widths []int
}

func regexLiteralVariants(re *syntax.Regexp) ([]literalVariant, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return []literalVariant{{}}, true
	case syntax.OpLiteral:
		text := asciiLowerLiteral(re.Rune)
		if text == "" || len(text) > maxLiteralVariantBytes {
			return nil, false
		}
		widths := make([]int, len(re.Rune))
		for i, r := range re.Rune {
			widths[i] = utf8.RuneLen(r)
			if re.Flags&syntax.FoldCase != 0 {
				widths[i] = foldedRuneMaxBytes(r)
			}
		}
		return []literalVariant{{text: text, widths: widths}}, true
	case syntax.OpCharClass:
		return charClassLiteralVariants(re.Rune)
	case syntax.OpCapture:
		return regexLiteralVariants(re.Sub[0])
	case syntax.OpConcat:
		variants := []literalVariant{{}}
		for _, sub := range re.Sub {
			subVariants, ok := regexLiteralVariants(sub)
			if !ok {
				return nil, false
			}
			variants, ok = concatLiteralVariants(variants, subVariants)
			if !ok {
				return nil, false
			}
		}
		return variants, true
	case syntax.OpAlternate:
		var variants []literalVariant
		for _, sub := range re.Sub {
			subVariants, ok := regexLiteralVariants(sub)
			if !ok {
				return nil, false
			}
			for _, variant := range subVariants {
				variants, ok = appendLiteralVariant(variants, variant)
				if !ok {
					return nil, false
				}
			}
		}
		return variants, len(variants) > 0
	case syntax.OpQuest:
		variants, ok := regexLiteralVariants(re.Sub[0])
		if !ok {
			return nil, false
		}
		return appendLiteralVariant(variants, literalVariant{})
	case syntax.OpRepeat:
		if re.Max < 0 || re.Max > 8 {
			return nil, false
		}
		return repeatLiteralVariants(re.Sub[0], re.Min, re.Max)
	default:
		return nil, false
	}
}

func charClassLiteralVariants(ranges []rune) ([]literalVariant, bool) {
	var variants []literalVariant
	enumerated := 0
	for i := 0; i+1 < len(ranges); i += 2 {
		lo, hi := ranges[i], ranges[i+1]
		if int64(hi)-int64(lo)+1 > int64(maxEnumeratedClassRunes-enumerated) {
			return nil, false
		}
		for r := lo; r <= hi; r++ {
			enumerated++
			canonical, ok := foldedASCIIByte(r)
			if !ok {
				return nil, false
			}
			variants, ok = appendLiteralVariant(variants, literalVariant{
				text:   string([]byte{canonical}),
				widths: []int{utf8.RuneLen(r)},
			})
			if !ok {
				return nil, false
			}
		}
	}
	return variants, len(variants) > 0
}

func foldedASCIIByte(r rune) (byte, bool) {
	if r < utf8.RuneSelf {
		b := byte(r)
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		return b, true
	}
	return ahocorasick.FoldRuneASCII(r)
}

func concatLiteralVariants(left, right []literalVariant) ([]literalVariant, bool) {
	if len(left) == 0 || len(right) == 0 || len(left)*len(right) > maxLiteralVariants*2 {
		return nil, false
	}
	variants := make([]literalVariant, 0, min(len(left)*len(right), maxLiteralVariants))
	for _, leftVariant := range left {
		for _, rightVariant := range right {
			if len(leftVariant.text)+len(rightVariant.text) > maxLiteralVariantBytes {
				return nil, false
			}
			widths := make([]int, 0, len(leftVariant.widths)+len(rightVariant.widths))
			widths = append(widths, leftVariant.widths...)
			widths = append(widths, rightVariant.widths...)
			var ok bool
			variants, ok = appendLiteralVariant(variants, literalVariant{
				text:   leftVariant.text + rightVariant.text,
				widths: widths,
			})
			if !ok {
				return nil, false
			}
		}
	}
	return variants, true
}

func appendLiteralVariant(variants []literalVariant, candidate literalVariant) ([]literalVariant, bool) {
	for i := range variants {
		if variants[i].text != candidate.text {
			continue
		}
		for widthIndex, width := range candidate.widths {
			variants[i].widths[widthIndex] = max(variants[i].widths[widthIndex], width)
		}
		return variants, true
	}
	if len(variants) >= maxLiteralVariants {
		return nil, false
	}
	return append(variants, candidate), true
}

func repeatLiteralVariants(re *syntax.Regexp, minCount, maxCount int) ([]literalVariant, bool) {
	unit, ok := regexLiteralVariants(re)
	if !ok {
		return nil, false
	}
	current := []literalVariant{{}}
	var variants []literalVariant
	for count := 0; count <= maxCount; count++ {
		if count >= minCount {
			for _, variant := range current {
				variants, ok = appendLiteralVariant(variants, variant)
				if !ok {
					return nil, false
				}
			}
		}
		if count != maxCount {
			current, ok = concatLiteralVariants(current, unit)
			if !ok {
				return nil, false
			}
		}
	}
	return variants, len(variants) > 0
}

func literalVariantsGuaranteeKeyword(variants []literalVariant, keywords []string) bool {
	if len(variants) == 0 {
		return false
	}
	for _, variant := range variants {
		matched := false
		for _, keyword := range keywords {
			if isASCIIString(keyword) && strings.Contains(variant.text, keyword) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func collectLiteralVariantMatchSpans(variants []literalVariant, keywords []string, prefix, suffix byteWidth, plans map[string]matchSpanPlan) {
	for _, variant := range variants {
		widths := make([]int, len(variant.widths)+1)
		for i, width := range variant.widths {
			widths[i+1] = widths[i] + width
		}
		for _, keyword := range keywords {
			if keyword == "" || !isASCIIString(keyword) {
				continue
			}
			for searchFrom := 0; searchFrom <= len(variant.text)-len(keyword); {
				offset := strings.Index(variant.text[searchFrom:], keyword)
				if offset < 0 {
					break
				}
				start := searchFrom + offset
				end := start + len(keyword)
				before := limitedByteWidth(addByteWidths(prefix, boundedByteWidth(widths[end])))
				after := limitedByteWidth(addByteWidths(suffix, boundedByteWidth(widths[len(variant.widths)]-widths[end])))
				mergeKeywordMatchSpan(plans, keyword, before, after)
				searchFrom = start + 1
			}
		}
	}
}

// guaranteesKeyword conservatively proves that every string accepted by re
// contains at least one configured ASCII keyword.
func guaranteesKeyword(re *syntax.Regexp, keywords []string) bool {
	switch re.Op {
	case syntax.OpLiteral:
		literal := asciiLowerLiteral(re.Rune)
		if literal == "" {
			return false
		}
		for _, keyword := range keywords {
			if isASCIIString(keyword) && strings.Contains(literal, keyword) {
				return true
			}
		}
		return false
	case syntax.OpCapture:
		return guaranteesKeyword(re.Sub[0], keywords)
	case syntax.OpConcat:
		var run []literalVariant
		for _, sub := range re.Sub {
			if guaranteesKeyword(sub, keywords) {
				return true
			}
			subVariants, ok := regexLiteralVariants(sub)
			if !ok {
				run = nil
				continue
			}
			if len(run) == 0 {
				run = []literalVariant{{}}
			}
			run, ok = concatLiteralVariants(run, subVariants)
			if !ok {
				run, ok = concatLiteralVariants([]literalVariant{{}}, subVariants)
			}
			if ok && literalVariantsGuaranteeKeyword(run, keywords) {
				return true
			}
			if !ok {
				run = nil
			}
		}
		return false
	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return false
		}
		for _, sub := range re.Sub {
			if !guaranteesKeyword(sub, keywords) {
				return false
			}
		}
		return true
	case syntax.OpPlus:
		return guaranteesKeyword(re.Sub[0], keywords)
	case syntax.OpRepeat:
		return re.Min > 0 && guaranteesKeyword(re.Sub[0], keywords)
	default:
		return false
	}
}

func asciiLowerLiteral(runes []rune) string {
	var local [128]byte
	if len(runes) > len(local) {
		return ""
	}
	buf := local[:len(runes)]
	for i, r := range runes {
		if r >= utf8.RuneSelf {
			return ""
		}
		b := byte(r)
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		buf[i] = b
	}
	return string(buf)
}

func isASCIIString(value string) bool {
	for i := range value {
		if value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func regexMaxBytes(re *syntax.Regexp) (int, bool) {
	width := regexByteWidth(re)
	return width.bytes, width.bounded
}

func regexByteWidth(re *syntax.Regexp) byteWidth {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return boundedByteWidth(0)
	case syntax.OpLiteral:
		width := 0
		for _, r := range re.Rune {
			runeWidth := utf8.RuneLen(r)
			if re.Flags&syntax.FoldCase != 0 {
				runeWidth = foldedRuneMaxBytes(r)
			}
			if !addWidth(&width, runeWidth) {
				return byteWidth{}
			}
		}
		return boundedByteWidth(width)
	case syntax.OpCharClass:
		return boundedByteWidth(charClassMaxBytes(re.Rune))
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return boundedByteWidth(utf8.UTFMax)
	case syntax.OpCapture:
		return regexByteWidth(re.Sub[0])
	case syntax.OpConcat:
		width := boundedByteWidth(0)
		for _, sub := range re.Sub {
			width = addByteWidths(width, regexByteWidth(sub))
		}
		return width
	case syntax.OpAlternate:
		width := boundedByteWidth(0)
		for _, sub := range re.Sub {
			subWidth := regexByteWidth(sub)
			if !subWidth.bounded {
				return byteWidth{}
			}
			width.bytes = max(width.bytes, subWidth.bytes)
		}
		return width
	case syntax.OpQuest:
		return regexByteWidth(re.Sub[0])
	case syntax.OpRepeat:
		subWidth := regexByteWidth(re.Sub[0])
		if re.Max < 0 {
			if subWidth.bounded && subWidth.bytes == 0 {
				return boundedByteWidth(0)
			}
			return byteWidth{}
		}
		return repeatByteWidth(subWidth, re.Max)
	case syntax.OpStar, syntax.OpPlus:
		subWidth := regexByteWidth(re.Sub[0])
		if !subWidth.bounded || subWidth.bytes != 0 {
			return byteWidth{}
		}
		return boundedByteWidth(0)
	default:
		return byteWidth{}
	}
}

func foldedRuneMaxBytes(r rune) int {
	maxBytes := utf8.RuneLen(r)
	for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
		maxBytes = max(maxBytes, utf8.RuneLen(folded))
	}
	return maxBytes
}

func charClassMaxBytes(ranges []rune) int {
	maxBytes := 0
	for i := 1; i < len(ranges); i += 2 {
		hi := ranges[i]
		switch {
		case hi >= 1<<16:
			return utf8.UTFMax
		case hi >= 1<<11:
			maxBytes = max(maxBytes, 3)
		case hi >= utf8.RuneSelf:
			maxBytes = max(maxBytes, 2)
		default:
			maxBytes = max(maxBytes, 1)
		}
	}
	return maxBytes
}

func addWidth(total *int, width int) bool {
	if width < 0 || *total > math.MaxInt-width {
		return false
	}
	*total += width
	return true
}
