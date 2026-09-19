package scan

import (
	"regexp/syntax"
	"unicode/utf8"
)

// compilePathSuffixes proves a finite, mandatory suffix immediately before
// an end-of-text anchor. Other path expressions retain their normal search.
func compilePathSuffixes(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil || re.Op != syntax.OpConcat || len(re.Sub) < 2 || re.Sub[len(re.Sub)-1].Op != syntax.OpEndText {
		return nil
	}
	var suffixes []string
	for start := len(re.Sub) - 2; start >= 0; start-- {
		suffix := &syntax.Regexp{Op: syntax.OpConcat, Sub: re.Sub[start : len(re.Sub)-1]}
		words, ok := foldedLiterals(suffix)
		if !ok {
			break
		}
		for _, word := range words {
			if word == "" {
				return nil
			}
		}
		suffixes = words
	}
	return suffixes
}

func pathSuffixPossible(path string, suffixes []string) bool {
	if len(suffixes) == 0 {
		return true
	}
	for _, suffix := range suffixes {
		possible := true
		for i := 1; i <= len(suffix); i++ {
			if i > len(path) {
				possible = false
				break
			}
			b := path[len(path)-i]
			// Unicode case folds can change byte width. Let the regex decide.
			if b >= utf8.RuneSelf {
				return true
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != suffix[len(suffix)-i] {
				possible = false
				break
			}
		}
		if possible {
			return true
		}
	}
	return false
}
