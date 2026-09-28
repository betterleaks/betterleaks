package scan

import (
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
)

func TestLeadingLiterals(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    []string
		fold    bool
		ok      bool
	}{
		{`abc`, []string{"abc"}, false, true},
		{`(?i)(?:key|token|secret)\s*=`, []string{"key", "secret", "token"}, true, true},
		{`\b(?:AccountKey|(?:azure[_\s.-]*)?key)\b`, []string{"accountkey", "azure", "key"}, false, true},
		{`(?-i:[Aa]pi|API)_key`, []string{"api_key"}, true, true},
		{`\b(re_[1-9A-HJ-NP-Za-km-z]{8})`, []string{"re_"}, false, true},
		{`(?:^|[^a-z])key`, nil, false, false},
		{`[a-z0-9]{32}`, nil, false, false},
		{`x*key`, []string{"key", "x"}, false, true},
		{`.key`, nil, false, false},
		{`(?i)pass(?:word)?\b[:=]`, []string{"pass"}, true, true},
	} {
		got, fold, ok := leadingLiterals(tc.pattern)
		require.Equal(t, tc.ok, ok, tc.pattern)
		if !ok {
			continue
		}
		// The parser reports fold-case literals in upper case; the scanner
		// lowercases every literal for the case-folding automaton.
		lowered := make([]string, 0, len(got))
		for _, literal := range got {
			lowered = append(lowered, lowerASCII(literal))
		}
		sort.Strings(lowered)
		require.Equal(t, tc.want, slices.Compact(lowered), tc.pattern)
		require.Equal(t, tc.fold, fold, tc.pattern)
	}
}

// Every match of an anchored default rule must begin at an offset where the
// keyword automaton reports one of its leading literals, so the anchored
// search must return exactly what an unanchored search returns.
func TestLeadingLiteralsCoverDefaultRuleMatches(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	scanner, err := New(cfg, WithRegexEngine(re2.RE2{}))
	require.NoError(t, err)

	anchored := 0
	rng := rand.New(rand.NewSource(7))
	for i := range scanner.rulesBySpecificity {
		rule := &scanner.rulesBySpecificity[i]
		if rule.leads == nil {
			continue
		}
		anchored++
		require.NoError(t, rule.regex.Compile())
		matcher := ahocorasick.Compile(rule.leads, true)

		pieces := append([]string{}, rule.leads...)
		pieces = append(pieces, rule.rule.Keywords...)
		pieces = append(pieces, " ", "\n", "=", ":", "\"", "'", "_", "-", "AKIAIOSFODNN7EXAMPLE",
			"abcdefghijklmnopqrstuvwxyz0123456789", "hunter2", "ZXlKaGJHY2lPaU", "://user:pw@host",
			"0123456789abcdef0123456789abcdef", "==", "-----BEGIN PRIVATE KEY-----")
		for round := 0; round < 40; round++ {
			var b strings.Builder
			for n := rng.Intn(12); n > 0; n-- {
				piece := pieces[rng.Intn(len(pieces))]
				if rng.Intn(3) == 0 {
					piece = strings.ToUpper(piece)
				}
				b.WriteString(piece)
			}
			text := b.String()

			var starts []int
			matcher.Visit(text, func(_, start, _ int) bool {
				starts = append(starts, start)
				return true
			})
			sort.Ints(starts)
			starts = slices.Compact(starts)

			want := rule.regex.FindAllStringSubmatchIndex(text, -1)
			got, ok := rule.regex.FindAllStringSubmatchIndexAt(text, starts, -1)
			require.True(t, ok)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("rule %s text %q: anchored %v, unanchored %v (leads %v)", rule.rule.ID, text, got, want, rule.leads)
			}
		}
	}
	require.Greater(t, anchored, 100, "most default rules should anchor")
}

func TestLeadingLiteralsSkipWithoutAnchoredEngine(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	scanner, err := New(cfg)
	require.NoError(t, err)
	for _, rule := range scanner.rulesBySpecificity {
		require.Nil(t, rule.leads, rule.rule.ID)
	}
}
