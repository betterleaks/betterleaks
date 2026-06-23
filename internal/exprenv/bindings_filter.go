package exprenv

import (
	"math"
	"sort"
	"strings"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/betterleaks/betterleaks/internal/words"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

var (
	regexCache  sync.Map // string -> *blregexp.Regexp
	acTrieCache sync.Map // string -> *ahocorasick.Trie
)

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

func getOrBuildTrie(terms []string) *ahocorasick.Trie {
	if len(terms) == 0 {
		return nil
	}
	key := sortedKey(terms)
	if v, ok := acTrieCache.Load(key); ok {
		return v.(*ahocorasick.Trie)
	}
	trie := ahocorasick.NewTrieBuilder().AddStrings(terms).Build()
	acTrieCache.Store(key, trie)
	return trie
}

func matchesAny(s string, patterns any) bool {
	re := getOrCompileJoinedRegex(toStringSlice(patterns))
	return re != nil && re.MatchString(s)
}

func containsAny(s string, terms any) bool {
	trie := getOrBuildTrie(toStringSlice(terms))
	return trie != nil && trie.MatchFirstString(strings.ToLower(s)) != nil
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

func celShannonEntropy(s string) float64 {
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

var celNewlineReplacer = strings.NewReplacer("\n", "", "\r", "")

func (rt *runtimeBindings) failsTokenEfficiency(secret string) bool {
	if rt.tokenizer == nil {
		return false
	}
	return celFailsTokenEfficiency(rt.tokenizer, secret)
}

func celFailsTokenEfficiency(tke *tiktoken.Tiktoken, secret string) bool {
	analyzed := secret
	if len(analyzed) < 20 && strings.ContainsAny(analyzed, "\n\r") {
		analyzed = celNewlineReplacer.Replace(analyzed)
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
