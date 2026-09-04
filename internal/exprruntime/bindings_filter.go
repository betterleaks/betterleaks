package exprruntime

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	"github.com/betterleaks/betterleaks/v2/internal/words"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	ahocorasick "github.com/rrethy/ahocorasick"
)

func sha256Fingerprint(value string) string {
	return fingerprint.Format(fingerprint.Sum([]byte(value)))
}

var (
	regexCache  sync.Map // string -> *blregexp.Regexp
	acTrieCache sync.Map // string -> *ahocorasick.Matcher
)

func filterNamespace(rt *runtimeBindings) map[string]any {
	return map[string]any{
		"matchesAny":           matchesAny,
		"findMatch":            findMatch,
		"containsAny":          containsAny,
		"startsWithAny":        startsWithAny,
		"intersects":           intersects,
		"entropy":              shannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
		"tokenRatio":           rt.tokenRatio,
	}
}

func (rt *runtimeBindings) setConfidence(value string) (string, error) {
	if !confidence.Valid(value) {
		return "", fmt.Errorf("filter.setConfidence: invalid confidence %q (expected low, medium, or high)", value)
	}
	rt.attrs.(map[string]string)[confidence.Attribute] = value
	return value, nil
}

func orderedKey(ss []string) string { return strings.Join(ss, "\x00") }

func sortedKey(ss []string) string {
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

func getOrCompileJoinedRegex(patterns []string) (*blregexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	key := orderedKey(patterns)
	if v, ok := regexCache.Load(key); ok {
		return v.(*blregexp.Regexp), nil
	}
	parts := make([]string, len(patterns))
	for i, p := range patterns {
		parts[i] = "(?:" + p + ")"
	}
	re, err := blregexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		for _, pattern := range patterns {
			if _, patternErr := blregexp.Compile(pattern); patternErr != nil {
				return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, patternErr)
			}
		}
		return nil, fmt.Errorf("compile regex patterns: %w", err)
	}
	regexCache.Store(key, re)
	return re, nil
}

func getOrBuildTrie(terms []string) *ahocorasick.Matcher {
	if len(terms) == 0 {
		return nil
	}
	normalized := make([]string, len(terms))
	for i, term := range terms {
		normalized[i] = strings.ToLower(term)
	}
	key := sortedKey(normalized)
	if v, ok := acTrieCache.Load(key); ok {
		return v.(*ahocorasick.Matcher)
	}
	trie := ahocorasick.CompileStrings(normalized)
	acTrieCache.Store(key, trie)
	return trie
}

func matchesAny(values, patterns any) (bool, error) {
	re, err := getOrCompileJoinedRegex(toStringSlice(patterns))
	if err != nil || re == nil {
		return false, err
	}
	return anyString(values, re.MatchString), nil
}

func findMatch(s, pattern string) (string, error) {
	re, err := getOrCompileJoinedRegex([]string{pattern})
	if err != nil || re == nil {
		return "", err
	}
	return re.FindString(s), nil
}

func containsAny(values, terms any) bool {
	trie := getOrBuildTrie(toStringSlice(terms))
	return trie != nil && anyString(values, func(value string) bool {
		return len(trie.FindAllString(strings.ToLower(value))) > 0
	})
}

func startsWithAny(values, prefixes any) bool {
	prefixesList := toStringSlice(prefixes)
	return len(prefixesList) > 0 && anyString(values, func(value string) bool {
		for _, prefix := range prefixesList {
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
		return false
	})
}

func intersects(values, candidates any) bool {
	candidateList := toStringSlice(candidates)
	return len(candidateList) > 0 && anyString(values, func(value string) bool {
		for _, candidate := range candidateList {
			if value == candidate {
				return true
			}
		}
		return false
	})
}

// anyString applies match to a string or every string in a list. Returning
// false for mixed-type lists keeps malformed dynamic Expr values conservative.
func anyString(value any, match func(string) bool) bool {
	switch value := value.(type) {
	case string:
		return match(value)
	case []string:
		for _, item := range value {
			if match(item) {
				return true
			}
		}
	case []any:
		for _, item := range value {
			if _, ok := item.(string); !ok {
				return false
			}
		}
		for _, item := range value {
			if match(item.(string)) {
				return true
			}
		}
	}
	return false
}

func toStringSlice(v any) []string {
	switch ss := v.(type) {
	case []string:
		return ss
	case []any:
		out := make([]string, 0, len(ss))
		for _, elem := range ss {
			s, ok := elem.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var newlineReplacer = strings.NewReplacer("\n", "", "\r", "")

func (rt *runtimeBindings) tokenCounterInstance() *tokenizer.Counter {
	if rt.tokenCounter == nil {
		if rt.tokenCounterProvider == nil {
			return nil
		}
		rt.tokenCounter = rt.tokenCounterProvider()
	}
	return rt.tokenCounter
}

func (rt *runtimeBindings) failsTokenEfficiency(secret string) bool {
	counter := rt.tokenCounterInstance()
	return counter != nil && failsTokenEfficiency(counter, secret)
}

func (rt *runtimeBindings) tokenRatio(secret string) float64 {
	counter := rt.tokenCounterInstance()
	if counter == nil {
		return 0
	}
	_, ratio, _ := calculateTokenRatio(counter, secret)
	return ratio
}

func calculateTokenRatio(counter *tokenizer.Counter, secret string) (string, float64, bool) {
	analyzed := secret
	if len(analyzed) < 20 && strings.ContainsAny(analyzed, "\n\r") {
		analyzed = newlineReplacer.Replace(analyzed)
	}
	tokenCount := counter.Count(analyzed)
	if tokenCount == 0 {
		return analyzed, 0, false
	}
	return analyzed, float64(len(analyzed)) / float64(tokenCount), true
}

func failsTokenEfficiency(counter *tokenizer.Counter, secret string) bool {
	analyzed, ratio, ok := calculateTokenRatio(counter, secret)
	if !ok {
		return false
	}
	if len(words.HasMatchInList(analyzed, 5)) > 0 {
		return true
	}
	threshold := 2.5
	if len(analyzed) < 12 {
		threshold = 2.1
		if len(words.HasMatchInList(analyzed, 4)) == 0 {
			threshold = 2.5
		}
	}
	return ratio >= threshold
}
