package scan

import (
	"regexp/syntax"
	"sort"
	"strings"
)

// maxLeadingLiterals bounds the literal set derived for one rule. Larger sets
// stop being selective, so the analysis gives up instead of growing them.
const maxLeadingLiterals = maxAnchorLiterals

// maxClassLiterals bounds how many runes a leading character class may
// contribute. Wider classes (identifier or base64 alphabets) would only yield
// single-byte literals that anchoring rejects anyway.
const maxClassLiterals = 16

// leadingLiterals derives a set of ASCII literals such that every match of
// pattern begins with one of them. It returns ok=false when no bounded set
// exists (the expression can start with a wide class, any character, or an
// unparsable construct). fold reports that some literal is matched
// case-insensitively; searching every literal case-insensitively then remains
// a superset of true match starts, which is all callers need because each
// candidate is verified with an anchored match.
//
// The result lets the detector try the rule's regex only at candidate offsets
// found by the keyword automaton. Unanchored RE2 searches for expressions such
// as (?i)(?:key|token|secret)...{10,150} build a huge DFA that thrashes its
// cache under many concurrent scanners; anchored searches from a fixed offset
// stay small.
func leadingLiterals(pattern string) (literals []string, fold bool, ok bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false, false
	}
	return leadingLiteralsOf(re)
}

// leadingLiteralsOf is leadingLiterals for a parsed expression; re is read,
// never modified.
func leadingLiteralsOf(re *syntax.Regexp) (literals []string, fold bool, ok bool) {
	set, nullable, _, ok := prefixSet(re.Simplify())
	if !ok || nullable || len(set.items) == 0 {
		return nil, false, false
	}
	for _, lit := range set.items {
		if lit == "" {
			return nil, false, false
		}
	}
	sort.Strings(set.items)
	return set.items, set.fold, true
}

type literalSet struct {
	items []string
	fold  bool
}

func (s *literalSet) add(lit string, fold bool) bool {
	for _, existing := range s.items {
		if existing == lit {
			s.fold = s.fold || fold
			return true
		}
	}
	if len(s.items) >= maxLeadingLiterals {
		return false
	}
	s.items = append(s.items, lit)
	s.fold = s.fold || fold
	return true
}

// prefixSet returns literals that begin every match of re. nullable reports
// that re can match the empty string, so a following element may start the
// match instead. exact reports that every match of re is one of the literals
// in full, which lets a concatenation extend them with what follows.
func prefixSet(re *syntax.Regexp) (set literalSet, nullable, exact, ok bool) {
	switch re.Op {
	case syntax.OpLiteral:
		if !asciiRunes(re.Rune) {
			return set, false, false, false
		}
		set.add(string(re.Rune), re.Flags&syntax.FoldCase != 0)
		return set, false, true, true

	case syntax.OpCharClass:
		// Rune is a list of inclusive [lo, hi] ranges. Case folding has already
		// been expanded into the class by the parser, which also adds the two
		// non-ASCII runes whose simple fold is ASCII (U+017F LONG S and U+212A
		// KELVIN SIGN); the keyword automaton folds those the same way.
		count := 0
		for i := 0; i < len(re.Rune); i += 2 {
			count += int(re.Rune[i+1]-re.Rune[i]) + 1
		}
		if count == 0 || count > maxClassLiterals+2 {
			return set, false, false, false
		}
		for i := 0; i < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				switch {
				case r <= 127:
					if !set.add(string(r), false) {
						return set, false, false, false
					}
				case r == 'ſ':
					if !set.add("s", true) {
						return set, false, false, false
					}
				case r == 'K':
					if !set.add("k", true) {
						return set, false, false, false
					}
				default:
					return set, false, false, false
				}
			}
		}
		return set, false, true, true

	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		// Zero-width: contributes no bytes; the next element starts the match.
		return set, true, false, true

	case syntax.OpCapture:
		return prefixSet(re.Sub[0])

	case syntax.OpStar, syntax.OpQuest:
		set, _, _, ok = prefixSet(re.Sub[0])
		return set, true, false, ok

	case syntax.OpPlus:
		set, nullable, _, ok = prefixSet(re.Sub[0])
		return set, nullable, false, ok

	case syntax.OpRepeat:
		set, nullable, _, ok = prefixSet(re.Sub[0])
		return set, nullable || re.Min == 0, false, ok

	case syntax.OpAlternate:
		exact = true
		for _, sub := range re.Sub {
			subSet, subNullable, subExact, subOK := prefixSet(sub)
			if !subOK {
				return set, false, false, false
			}
			for _, lit := range subSet.items {
				if !set.add(lit, subSet.fold) {
					return set, false, false, false
				}
			}
			nullable = nullable || subNullable
			exact = exact && subExact
		}
		return set, nullable, exact, true

	case syntax.OpConcat:
		return concatPrefixSet(re.Sub)

	default:
		// OpAnyChar, OpAnyCharNotNL, OpNoMatch and anything unexpected.
		return set, false, false, false
	}
}

// maxProductLiterals caps the growth from extending head literals with what
// follows. Past it the shorter head set is kept: still sound, less selective.
const maxProductLiterals = 16

func concatPrefixSet(subs []*syntax.Regexp) (set literalSet, nullable, exact, ok bool) {
	if len(subs) == 0 {
		return set, true, true, true
	}
	head, headNullable, headExact, ok := prefixSet(subs[0])
	if !ok {
		return set, false, false, false
	}
	if len(subs) == 1 {
		return head, headNullable, headExact, true
	}
	rest, restNullable, restExact, restOK := concatPrefixSet(subs[1:])
	if !headNullable {
		if !restOK || !headExact || len(head.items) == 0 || len(rest.items) == 0 || !worthExtending(rest.items) {
			// A non-empty head already begins every match.
			return head, false, false, true
		}
		// Every match is a head literal followed by a match of rest, so the
		// product is a longer, more selective set.
		var product literalSet
		for _, h := range head.items {
			for _, r := range rest.items {
				if len(product.items) >= maxProductLiterals || !product.add(h+r, head.fold || rest.fold) {
					return head, false, false, true
				}
			}
			if restNullable && !product.add(h, head.fold) {
				return head, false, false, true
			}
		}
		return product, false, restExact, true
	}
	if !restOK {
		return set, false, false, false
	}
	// head may be empty, so the match can begin with either side.
	for _, lit := range rest.items {
		if !head.add(lit, rest.fold) {
			return set, false, false, false
		}
	}
	return head, restNullable, false, true
}

// worthExtending reports whether appending rest's literals to a head makes the
// set more selective. Single-byte continuations (a separator class such as
// [_\s.-] or a quote) multiply the set without narrowing it, and can push a
// rule past the anchoring cap; the head alone is the better leading set.
func worthExtending(rest []string) bool {
	for _, lit := range rest {
		if len(lit) < 2 {
			return false
		}
	}
	return true
}

func asciiRunes(runes []rune) bool {
	for _, r := range runes {
		if r > 127 {
			return false
		}
	}
	return true
}

// lowerASCII lowercases ASCII letters only, matching the keyword automaton's
// case folding without touching other bytes.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// minAnchorLiteral is the shortest leading literal worth anchoring on. Shorter
// literals occur too often for candidate offsets to save work.
const minAnchorLiteral = 3

// maxAnchorLiterals bounds the leading-literal set a rule may anchor on.
const maxAnchorLiterals = 32

func selectiveLiterals(literals []string) bool {
	if len(literals) == 0 || len(literals) > maxAnchorLiterals {
		return false
	}
	for _, literal := range literals {
		if len(literal) < minAnchorLiteral {
			return false
		}
	}
	return true
}
