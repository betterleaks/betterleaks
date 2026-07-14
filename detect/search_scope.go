package detect

import (
	"math"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/config"
)

const (
	maxExactVariants = 4096
	maxExactBytes    = 64
)

// inferKeywordScope returns a conservative byte radius around keyword matches.
// Zero keeps full-fragment evaluation.
func inferKeywordScope(rule config.Rule) int {
	if rule.Regex == nil || len(rule.Keywords) == 0 {
		return 0
	}
	re, err := syntax.Parse(rule.Regex.String(), syntax.Perl)
	if err != nil || !requiresKeyword(re, rule.Keywords) {
		return 0
	}
	maxLen, finite := maxRegexBytes(re)
	if !finite || maxLen == 0 {
		return 0
	}
	return maxLen
}

func requiresKeyword(re *syntax.Regexp, keywords []string) bool {
	switch re.Op {
	case syntax.OpLiteral:
		return containsKeyword(strings.ToLower(string(re.Rune)), keywords)
	case syntax.OpCapture:
		return requiresKeyword(re.Sub[0], keywords)
	case syntax.OpConcat:
		variants := []string{""}
		for _, sub := range re.Sub {
			if requiresKeyword(sub, keywords) {
				return true
			}
			part, ok := exactStrings(sub)
			if !ok {
				variants = []string{""}
				continue
			}
			variants, ok = combineStrings(variants, part)
			if !ok {
				variants = []string{""}
				continue
			}
			allContain := true
			for _, variant := range variants {
				if !containsKeyword(strings.ToLower(variant), keywords) {
					allContain = false
					break
				}
			}
			if allContain {
				return true
			}
		}
		return false
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !requiresKeyword(sub, keywords) {
				return false
			}
		}
		return len(re.Sub) > 0
	case syntax.OpPlus:
		return requiresKeyword(re.Sub[0], keywords)
	case syntax.OpRepeat:
		if re.Min > 0 {
			return requiresKeyword(re.Sub[0], keywords)
		}
	}

	variants, ok := exactStrings(re)
	if !ok || len(variants) == 0 {
		return false
	}
	for _, variant := range variants {
		if !containsKeyword(strings.ToLower(variant), keywords) {
			return false
		}
	}
	return true
}

func containsKeyword(s string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(s, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func maxRegexBytes(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return 0, true
	case syntax.OpLiteral:
		total := 0
		for _, r := range re.Rune {
			n := maxFoldedRuneBytes(r, re.Flags&syntax.FoldCase != 0)
			if n > math.MaxInt-total {
				return 0, false
			}
			total += n
		}
		return total, true
	case syntax.OpCharClass:
		maxLen := 1
		for i := 1; i < len(re.Rune); i += 2 {
			maxLen = max(maxLen, utf8.RuneLen(re.Rune[i]))
		}
		return maxLen, true
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return utf8.UTFMax, true
	case syntax.OpCapture:
		return maxRegexBytes(re.Sub[0])
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			n, finite := maxRegexBytes(sub)
			if !finite || n > math.MaxInt-total {
				return 0, false
			}
			total += n
		}
		return total, true
	case syntax.OpAlternate:
		longest := 0
		for _, sub := range re.Sub {
			n, finite := maxRegexBytes(sub)
			if !finite {
				return 0, false
			}
			longest = max(longest, n)
		}
		return longest, true
	case syntax.OpQuest:
		return maxRegexBytes(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, false
		}
		n, finite := maxRegexBytes(re.Sub[0])
		if !finite || (n > 0 && re.Max > math.MaxInt/n) {
			return 0, false
		}
		return n * re.Max, true
	case syntax.OpStar, syntax.OpPlus:
		return 0, false
	default:
		return 0, false
	}
}

func maxFoldedRuneBytes(r rune, folded bool) int {
	maxLen := max(utf8.RuneLen(r), 1)
	if !folded {
		return maxLen
	}
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		maxLen = max(maxLen, utf8.RuneLen(next))
	}
	return maxLen
}

func exactStrings(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary,
		syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpLiteral:
		literal := string(re.Rune)
		return []string{literal}, len(literal) <= maxExactBytes
	case syntax.OpCharClass:
		var out []string
		for i := 0; i < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if int64(hi)-int64(lo)+1 > int64(maxExactVariants-len(out)) {
				return nil, false
			}
			for r := lo; ; r++ {
				out = append(out, string(r))
				if r == hi {
					break
				}
			}
		}
		return out, true
	case syntax.OpCapture:
		return exactStrings(re.Sub[0])
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			part, ok := exactStrings(sub)
			if !ok {
				return nil, false
			}
			out, ok = combineStrings(out, part)
			if !ok {
				return nil, false
			}
		}
		return out, true
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			part, ok := exactStrings(sub)
			if !ok || len(out)+len(part) > maxExactVariants {
				return nil, false
			}
			out = append(out, part...)
		}
		return out, true
	case syntax.OpQuest:
		part, ok := exactStrings(re.Sub[0])
		if !ok || len(part)+1 > maxExactVariants {
			return nil, false
		}
		return append([]string{""}, part...), true
	case syntax.OpRepeat:
		if re.Min != re.Max || re.Max < 0 {
			return nil, false
		}
		part, ok := exactStrings(re.Sub[0])
		if !ok {
			return nil, false
		}
		out := []string{""}
		for range re.Max {
			out, ok = combineStrings(out, part)
			if !ok {
				return nil, false
			}
		}
		return out, true
	default:
		return nil, false
	}
}

func combineStrings(left, right []string) ([]string, bool) {
	if len(left) == 0 || len(right) == 0 || len(left) > maxExactVariants/len(right) {
		return nil, false
	}
	out := make([]string, 0, len(left)*len(right))
	for _, a := range left {
		for _, b := range right {
			if len(a)+len(b) > maxExactBytes {
				return nil, false
			}
			out = append(out, a+b)
		}
	}
	return out, true
}
