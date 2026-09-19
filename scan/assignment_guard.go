package scan

import (
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// assignmentGuard is a necessary (not sufficient) condition following an
// exact keyword prefix. It is inferred from the regex, never from a rule ID.
// Unsupported syntax, Unicode input and ambiguous bounds remain candidates.
type assignmentGuard struct {
	identifier    [128]bool
	padding       [128]bool
	operator      [128]bool
	identifierMax int
	paddingMax    int
}

func inferAssignmentGuard(re *syntax.Regexp, keywords []string) *assignmentGuard {
	if re.Op != syntax.OpConcat || len(re.Sub) < 4 {
		return nil
	}
	literals, ok := foldedLiterals(re.Sub[0])
	if !ok || len(literals) == 0 {
		return nil
	}
	for _, literal := range literals {
		if literal == "" {
			return nil
		}
		found := false
		for _, keyword := range keywords {
			if literal == strings.ToLower(keyword) {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	g := &assignmentGuard{}
	if g.identifier, g.identifierMax, ok = guardOptionalClass(re.Sub[1]); !ok {
		return nil
	}
	if g.padding, g.paddingMax, ok = guardOptionalClass(re.Sub[2]); !ok {
		return nil
	}
	if g.operator, ok = guardFirstBytes(re.Sub[3]); !ok {
		return nil
	}
	for b, operator := range g.operator {
		// Greedy consumption of the optional classes must not consume an
		// operator that an earlier split could have accepted.
		if operator && (g.identifier[b] || g.padding[b]) {
			return nil
		}
	}
	return g
}

func (g *assignmentGuard) possible(raw string, end int) bool {
	i := end
	for count := 0; count < g.identifierMax && i < len(raw); count++ {
		b := raw[i]
		if b >= utf8.RuneSelf {
			return true
		}
		if !g.identifier[b] {
			break
		}
		i++
	}
	for count := 0; count < g.paddingMax && i < len(raw); count++ {
		b := raw[i]
		if b >= utf8.RuneSelf {
			return true
		}
		if !g.padding[b] {
			break
		}
		i++
	}
	return i < len(raw) && (raw[i] >= utf8.RuneSelf || g.operator[raw[i]])
}

func guardOptionalClass(re *syntax.Regexp) (set [128]bool, max int, ok bool) {
	if re.Op != syntax.OpRepeat || re.Min != 0 || re.Max < 0 || re.Max > 64 || len(re.Sub) != 1 {
		return set, 0, false
	}
	set, ok = guardRuneSet(re.Sub[0])
	return set, re.Max, ok
}

func guardRuneSet(re *syntax.Regexp) (set [128]bool, ok bool) {
	switch re.Op {
	case syntax.OpCharClass:
		for b := range set {
			set[b] = runeInRanges(rune(b), re.Rune)
		}
		return set, true
	case syntax.OpLiteral:
		if len(re.Rune) != 1 {
			return set, false
		}
		for b := range set {
			set[b] = rune(b) == re.Rune[0] || re.Flags&syntax.FoldCase != 0 && strings.EqualFold(string(rune(b)), string(re.Rune[0]))
		}
		return set, true
	}
	return set, false
}

// guardFirstBytes requires a nonempty expression with an ASCII first rune.
// An operator's remaining syntax is deliberately left to the real regex.
func guardFirstBytes(re *syntax.Regexp) (set [128]bool, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 || re.Rune[0] >= 128 {
			return set, false
		}
		copy := *re
		copy.Rune = re.Rune[:1]
		return guardRuneSet(&copy)
	case syntax.OpCharClass:
		if len(re.Rune) == 0 || re.Rune[len(re.Rune)-1] >= 128 {
			return set, false
		}
		return guardRuneSet(re)
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return guardFirstBytes(re.Sub[0])
		}
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return guardFirstBytes(re.Sub[0])
		}
	case syntax.OpAlternate:
		if len(re.Sub) == 0 {
			return set, false
		}
		for _, sub := range re.Sub {
			part, valid := guardFirstBytes(sub)
			if !valid {
				return set, false
			}
			for b := range set {
				set[b] = set[b] || part[b]
			}
		}
		return set, true
	case syntax.OpRepeat:
		if re.Min > 0 && len(re.Sub) == 1 {
			return guardFirstBytes(re.Sub[0])
		}
	case syntax.OpPlus:
		if len(re.Sub) == 1 {
			return guardFirstBytes(re.Sub[0])
		}
	}
	return set, false
}

// Expand only small finite literal languages. Case-fold variants collapse to
// ASCII because the keyword visitor already recognizes their Unicode folds.
func foldedLiterals(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		var word strings.Builder
		for _, r := range re.Rune {
			b, ok := guardFoldASCII(r)
			if !ok {
				return nil, false
			}
			word.WriteByte(b)
		}
		return []string{word.String()}, true
	case syntax.OpCharClass:
		var words []string
		var seen [128]bool
		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i+1]-re.Rune[i] > 128 {
				return nil, false
			}
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				b, ok := guardFoldASCII(r)
				if !ok {
					return nil, false
				}
				if !seen[b] {
					seen[b] = true
					words = append(words, string(b))
				}
			}
		}
		return words, true
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return foldedLiterals(re.Sub[0])
		}
	case syntax.OpAlternate, syntax.OpConcat:
		words := []string{}
		if re.Op == syntax.OpConcat {
			words = []string{""}
		}
		for _, sub := range re.Sub {
			part, ok := foldedLiterals(sub)
			if !ok {
				return nil, false
			}
			if re.Op == syntax.OpAlternate {
				words = append(words, part...)
			} else {
				if len(words)*len(part) > 1024 {
					return nil, false
				}
				var combined []string
				for _, a := range words {
					for _, b := range part {
						if len(a)+len(b) > 128 {
							return nil, false
						}
						combined = append(combined, a+b)
					}
				}
				words = combined
			}
			if len(words) > 1024 {
				return nil, false
			}
		}
		return words, true
	}
	return nil, false
}

func compileAssignmentGuard(pattern string, keywords []string) *assignmentGuard {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	return inferAssignmentGuard(re, keywords)
}

// The keyword matcher folds these two Unicode runes to ASCII as well.
func guardFoldASCII(r rune) (byte, bool) {
	if r == '\u017f' {
		r = 's'
	}
	if r == '\u212a' {
		r = 'k'
	}
	if r < 0 || r >= utf8.RuneSelf {
		return 0, false
	}
	b := byte(r)
	if b >= 'A' && b <= 'Z' {
		b += 'a' - 'A'
	}
	return b, true
}

func runeInRanges(r rune, ranges []rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if r < ranges[i] {
			return false
		}
		if r <= ranges[i+1] {
			return true
		}
	}
	return false
}
