package exprruntime

import (
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/internal/words"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	tiktoken "github.com/pkoukk/tiktoken-go"
	ahocorasick "github.com/rrethy/ahocorasick"
)

var (
	regexCache  sync.Map // string -> *blregexp.Regexp
	acTrieCache sync.Map // string -> *ahocorasick.Matcher
)

func filterNamespace(rt *runtimeBindings) map[string]any {
	return map[string]any{
		"matchesAny":           matchesAny,
		"matchesAnyNearMatch":  rt.matchesAnyNearMatch,
		"containsAny":          containsAny,
		"containsAnyNearMatch": rt.containsAnyNearMatch,
		"entropy":              shannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
	}
}

func orderedKey(ss []string) string { return strings.Join(ss, "\x00") }

func sortedKey(ss []string) string {
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

func getOrCompileJoinedRegex(patterns []string) *blregexp.Regexp {
	if len(patterns) == 0 {
		return nil
	}
	key := orderedKey(patterns)
	if v, ok := regexCache.Load(key); ok {
		return v.(*blregexp.Regexp)
	}
	parts := make([]string, len(patterns))
	for i, p := range patterns {
		parts[i] = "(?:" + p + ")"
	}
	re, err := blregexp.Compile(strings.Join(parts, "|"))
	if err != nil {
		return nil
	}
	regexCache.Store(key, re)
	return re
}

func getOrBuildTrie(terms []string) *ahocorasick.Matcher {
	if len(terms) == 0 {
		return nil
	}
	key := sortedKey(terms)
	if v, ok := acTrieCache.Load(key); ok {
		return v.(*ahocorasick.Matcher)
	}
	trie := ahocorasick.CompileStrings(terms)
	acTrieCache.Store(key, trie)
	return trie
}

func matchesAny(s string, patterns any) bool {
	re := getOrCompileJoinedRegex(toStringSlice(patterns))
	return re != nil && re.MatchString(s)
}

func containsAny(s string, terms any) bool {
	trie := getOrBuildTrie(toStringSlice(terms))
	return trie != nil && len(trie.FindAllString(strings.ToLower(s))) > 0
}

// The finding argument makes these functions natural to call from Expr
// (filter.containsAnyNearMatch(finding, ...)). The match offsets live on the
// per-evaluation runtime because finding contains only the extracted match.
func (rt *runtimeBindings) matchesAnyNearMatch(_ any, patterns any, charsBefore, charsAfter int, limitToLine bool) bool {
	return matchesAny(rt.nearMatchText(charsBefore, charsAfter, limitToLine), patterns)
}

func (rt *runtimeBindings) containsAnyNearMatch(_ any, terms any, charsBefore, charsAfter int, limitToLine bool) bool {
	return containsAny(rt.nearMatchText(charsBefore, charsAfter, limitToLine), terms)
}

func (rt *runtimeBindings) nearMatchText(charsBefore, charsAfter int, limitToLine bool) string {
	w := rt.matchWindow
	if w.MatchStart < 0 || w.MatchEnd < w.MatchStart || w.MatchEnd > len(w.Raw) {
		return ""
	}
	// MatchWindow offsets and the requested distances are bytes, matching Go's
	// regexp indexes and string slicing. limitToLine further clamps the window.
	charsBefore = min(max(charsBefore, 0), w.MatchStart)
	charsAfter = min(max(charsAfter, 0), len(w.Raw)-w.MatchEnd)
	start, end := w.MatchStart-charsBefore, w.MatchEnd+charsAfter
	if limitToLine {
		if newline := strings.LastIndexAny(w.Raw[start:w.MatchStart], "\r\n"); newline >= 0 {
			start += newline + 1
		}
		if newline := strings.IndexAny(w.Raw[w.MatchEnd:end], "\r\n"); newline >= 0 {
			end = w.MatchEnd + newline
		}
	}
	return w.Raw[start:end]
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

func (rt *runtimeBindings) failsTokenEfficiency(secret string) bool {
	if rt.tokenizer == nil {
		if rt.tokenizerProvider == nil {
			return false
		}
		rt.tokenizer = rt.tokenizerProvider()
		if rt.tokenizer == nil {
			return false
		}
	}
	return failsTokenEfficiency(rt.tokenizer, secret)
}

func failsTokenEfficiency(tke *tiktoken.Tiktoken, secret string) bool {
	analyzed := secret
	if len(analyzed) < 20 && strings.ContainsAny(analyzed, "\n\r") {
		analyzed = newlineReplacer.Replace(analyzed)
	}
	tokens := tke.Encode(analyzed, nil, nil)
	if len(tokens) == 0 {
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
	return float64(len(analyzed))/float64(len(tokens)) >= threshold
}
