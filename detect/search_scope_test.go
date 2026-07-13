package detect

import (
	"math"
	"regexp/syntax"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func TestInferKeywordScope(t *testing.T) {
	for _, test := range []struct {
		name     string
		pattern  string
		keywords []string
		want     int
	}{
		{"bounded required keyword", `token=.{10}`, []string{"token"}, 46},
		{"keyword assembled across nodes", `passw(?:or)?d=.{2}`, []string{"passwd", "password"}, 17},
		{"keyword-free alternation branch", `(?:token|username)=.{10}`, []string{"token"}, 0},
		{"optional keyword", `(?:token)?value`, []string{"token"}, 0},
		{"unbounded expression", `token=.+`, []string{"token"}, 0},
		{"bounded repetition", `token[0-9]{2,4}`, []string{"token"}, 9},
		{"excessive bounded repetition", `token(?:ab){1000}`, []string{"token"}, 2005},
		{"unicode case-folded literal", `(?i:key)`, []string{"key"}, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := config.Rule{Regex: regexp.MustCompile(test.pattern), Keywords: test.keywords}
			require.Equal(t, test.want, inferKeywordScope(rule))
		})
	}
}

func TestScopeInferenceLimits(t *testing.T) {
	choice := &syntax.Regexp{Op: syntax.OpCharClass, Rune: []rune{'a', 'b'}}
	concat := &syntax.Regexp{Op: syntax.OpConcat, Sub: make([]*syntax.Regexp, 13)}
	for i := range concat.Sub {
		concat.Sub[i] = choice
	}
	_, exact := exactStrings(concat)
	require.False(t, exact)

	repeat := &syntax.Regexp{
		Op:  syntax.OpRepeat,
		Min: 1,
		Max: math.MaxInt,
		Sub: []*syntax.Regexp{{Op: syntax.OpLiteral, Rune: []rune("ab")}},
	}
	_, finite := maxRegexBytes(repeat)
	require.False(t, finite)
}

func TestDefaultScopeInventory(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	require.Equal(t, 537, inferKeywordScope(cfg.Rules["generic-api-key"]))
	require.Zero(t, inferKeywordScope(cfg.Rules["azure-app-configuration-connection-string"]))

	inferred := 0
	for _, rule := range cfg.Rules {
		if inferKeywordScope(rule) > 0 {
			inferred++
		}
	}
	require.GreaterOrEqual(t, inferred, 250)
}
