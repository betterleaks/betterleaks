package celenv

import (
	"math"
	"sort"
	"strings"
	"sync"

	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/words"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

var (
	// regexCache caches compiled joined-pattern regexes keyed by the joined pattern string.
	regexCache sync.Map // string → *blregexp.Regexp
	// acTrieCache caches Aho-Corasick tries keyed by a sorted join of the term list.
	acTrieCache sync.Map // string → *ahocorasick.Trie
)

// celListToStrings converts a CEL list value to a Go []string.
// Returns nil if val is not a list or contains non-string elements.
func celListToStrings(val ref.Val) []string {
	lister, ok := val.(traits.Lister)
	if !ok {
		return nil
	}
	sz := lister.Size()
	n, ok := sz.(types.Int)
	if !ok {
		return nil
	}
	result := make([]string, 0, int(n))
	it := lister.Iterator()
	for it.HasNext() == types.True {
		elem := it.Next()
		s, ok := elem.(types.String)
		if !ok {
			return nil
		}
		result = append(result, string(s))
	}
	return result
}

// orderedKey builds a stable cache key preserving insertion order (for regex patterns).
func orderedKey(ss []string) string { return strings.Join(ss, "\x00") }

// sortedKey builds a stable cache key independent of order (for containsAny terms).
func sortedKey(ss []string) string {
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return strings.Join(cp, "\x00")
}

// getOrCompileJoinedRegex returns a single compiled regex that matches any of the patterns.
// Results are cached by the ordered list of patterns.
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

// getOrBuildTrie returns an Aho-Corasick trie for the given terms.
// Results are cached by a sorted join of the terms.
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

// matchesAnyBinding returns the CEL function matchesAny(string, list<string>) → bool.
// Each element of the list is treated as a regex pattern.
// Compiled regexes are cached by the pattern list, so repeated calls with the same
// literal list (the common case for translated allowlists) pay only one regex match.
func matchesAnyBinding() cel.EnvOption {
	return cel.Function("matchesAny",
		cel.Overload("matchesAny_string_list",
			[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
			cel.BoolType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				str, ok := lhs.(types.String)
				if !ok {
					return types.Bool(false)
				}
				patterns := celListToStrings(rhs)
				if len(patterns) == 0 {
					return types.Bool(false)
				}
				re := getOrCompileJoinedRegex(patterns)
				if re == nil {
					return types.Bool(false)
				}
				return types.Bool(re.MatchString(string(str)))
			}),
		),
	)
}

// containsAnyBinding returns the CEL function containsAny(string, list<string>) → bool.
// Uses an Aho-Corasick trie for efficient multi-term substring matching.
// The string is lowercased before matching (mirrors Allowlist.ContainsStopWord).
func containsAnyBinding() cel.EnvOption {
	return cel.Function("containsAny",
		cel.Overload("containsAny_string_list",
			[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
			cel.BoolType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				str, ok := lhs.(types.String)
				if !ok {
					return types.Bool(false)
				}
				terms := celListToStrings(rhs)
				if len(terms) == 0 {
					return types.Bool(false)
				}
				trie := getOrBuildTrie(terms)
				if trie == nil {
					return types.Bool(false)
				}
				return types.Bool(trie.MatchFirstString(strings.ToLower(string(str))) != nil)
			}),
		),
	)
}

// entropyBinding returns the CEL function entropy(string) → double.
// Computes Shannon entropy in bits over the byte distribution of the string.
func entropyBinding() cel.EnvOption {
	return cel.Function("entropy",
		cel.Overload("entropy_string",
			[]*cel.Type{cel.StringType},
			cel.DoubleType,
			cel.UnaryBinding(func(val ref.Val) ref.Val {
				s, ok := val.(types.String)
				if !ok {
					return types.Double(0)
				}
				return types.Double(celShannonEntropy(string(s)))
			}),
		),
	)
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

// tokenEfficiencyOKBinding returns the CEL function tokenEfficiencyOK(string) → bool.
// Returns true if the secret is plausibly a secret (not an efficient/common token sequence).
// If tke is nil (tokenizer unavailable), always returns true — preserves existing behavior
// of skipping the filter when tiktoken fails to initialize.
func tokenEfficiencyOKBinding(tke *tiktoken.Tiktoken) cel.EnvOption {
	return cel.Function("tokenEfficiencyOK",
		cel.Overload("tokenEfficiencyOK_string",
			[]*cel.Type{cel.StringType},
			cel.BoolType,
			cel.UnaryBinding(func(val ref.Val) ref.Val {
				if tke == nil {
					return types.Bool(true)
				}
				s, ok := val.(types.String)
				if !ok {
					return types.Bool(true)
				}
				return types.Bool(!celFailsTokenEfficiency(tke, string(s)))
			}),
		),
	)
}

// celFailsTokenEfficiency encapsulates the token efficiency check from detect.go.
// Returns true if the secret tokenizes too efficiently (common natural-language text)
// and should be suppressed.
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

// fastBindings returns the CEL EnvOptions for bindings shared by PrefilterEnv and FilterEnv.
// tke may be nil; tokenEfficiencyOK will return true unconditionally in that case.
func fastBindings(tke *tiktoken.Tiktoken) []cel.EnvOption {
	return []cel.EnvOption{
		matchesAnyBinding(),
		containsAnyBinding(),
		entropyBinding(),
		tokenEfficiencyOKBinding(tke),
		// TODO add more bindings here as we come across new detection techniques.
	}
}
