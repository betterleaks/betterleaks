package scan

import (
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/lucasjones/reggen"
	"github.com/stretchr/testify/require"
)

func compileContextGuard(t testing.TB, pattern string, keywords []string) *contextGuard {
	t.Helper()
	re, err := syntax.Parse(pattern, syntax.Perl)
	require.NoError(t, err)
	return inferContextGuard(re, keywords)
}

func TestContextGuardInference(t *testing.T) {
	keywords := []string{"token", "secret"}
	for _, tc := range []struct {
		pattern string
		guarded bool
	}{
		{`(?i)token[ \t'"\w.-]{0,20}(?:=|:)([a-z]{10})`, true},
		{`(?i)(?:token|secret)\s*=\s*([a-z]{10})|<[\w.:-]{0,64}secret>([a-z]{10})`, true},
		{`(?i)(?:token[ \t]*=|<[\w]{0,8}secret[ \t]*>)([a-z]{10})`, true},
		{`\btoken=([a-z]{10})`, true},
		// A keyword-free alternative can match anywhere.
		{`(?:token=|key=)([a-z]{10})`, false},
		// A literal holding a keyword splits around it, at the earliest one.
		{`mytoken=([a-z]{10})`, true},
		{`tokensecret=([a-z]{10})`, true},
		{`secretx(?:token)=([a-z]{10})`, true},
		// Nothing constrains the hit.
		{`token`, false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			require.Equal(t, tc.guarded, compileContextGuard(t, tc.pattern, keywords) != nil)
		})
	}
}

func TestContextGuardGenericAPIKey(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	rule, ok := cfg.Rule("generic-api-key")
	require.True(t, ok)
	guard := compileContextGuard(t, rule.Regex, rule.Keywords)
	require.NotNil(t, guard)
	matcher := ahocorasick.Compile(rule.Keywords, true)
	// The guard checks the value's shape, not its entropy.
	value := strings.Repeat("x1", 16)
	for _, tc := range []struct {
		raw    string
		accept bool
	}{
		{"def access_level_for(user)", false},
		{"user.token_count + 1", false},
		{"api_key = '" + value + "'", true},
		{`"credential": {"value": "` + value + `"}`, true},
		{"<cfg:API_KEYS>\n<site>" + value + "</site>", true},
		{"secret\n\t= " + value, true},
	} {
		require.Equal(t, tc.accept, guardAccepts(guard, matcher, tc.raw), tc.raw)
	}
}

// Every default rule that gets a context guard must report the same
// findings as an unguarded, unwindowed scan of generated matches.
func TestContextGuardsPreserveGeneratedMatches(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	guarded := 0
	for _, rule := range cfg.Rules {
		if rule.Regex == "" || len(rule.Keywords) == 0 {
			continue
		}
		parsed, err := syntax.Parse(rule.Regex, syntax.Perl)
		require.NoError(t, err)
		if inferAssignmentGuard(parsed, rule.Keywords) != nil || inferContextGuard(parsed, rule.Keywords) == nil {
			continue
		}
		guarded++
		t.Run(rule.ID, func(t *testing.T) {
			// Filters and components could hide a missed match; keep only the regex.
			isolated := &config.Config{Rules: []config.Rule{{ID: rule.ID, Regex: rule.Regex, Keywords: rule.Keywords, ValueGroup: rule.ValueGroup}}}
			narrowed := mustNew(t, isolated)
			_, ok := narrowed.rulesBySpecificity[0].guard.(*contextGuard)
			require.True(t, ok)
			original := mustNew(t, isolated)
			original.rulesBySpecificity[0].guard = nil
			original.rulesBySpecificity[0].span = nil
			original.rulesBySpecificity[0].searchAnchors = nil
			clear(original.anchorRuleIndexes)

			generator, err := reggen.NewGenerator(rule.Regex)
			require.NoError(t, err)
			generator.SetSeed(1)
			for range 20 {
				value := generator.Generate(16)
				raw := strings.Repeat("ordinary text\n", 50) + value + "\n" + strings.Repeat("other text\n", 50) + value
				fragment := sources.Fragment{Raw: raw, StartLine: 1}
				require.Equal(t, original.detectFragment(t.Context(), fragment), narrowed.detectFragment(t.Context(), fragment), "generated %q", value)
			}
		})
	}
	require.NotZero(t, guarded)
	t.Logf("context guards for %d default rules", guarded)
}

// Search windows may be measured from a different keyword than the one the
// guard checks: the whole regex below expands to literals, and the window
// plan uses "secret" while the guard examines "token". Rejecting a hit must
// not remove the window that covers the match.
func TestContextGuardKeepsWindowsOfRejectedHits(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{
		ID: "mismatch", Regex: `token[._]production_secret=([a-z])`, Keywords: []string{"secret", "token"},
	}}}
	narrowed := mustNew(t, cfg)
	_, ok := narrowed.rulesBySpecificity[0].guard.(*contextGuard)
	require.True(t, ok)
	original := mustNew(t, cfg)
	original.rulesBySpecificity[0].guard = nil
	original.rulesBySpecificity[0].span = nil
	original.rulesBySpecificity[0].searchAnchors = nil
	clear(original.anchorRuleIndexes)
	for _, raw := range []string{
		"token.production_secret=a",
		strings.Repeat("filler\n", 100) + "token_production_secret=b\n" + strings.Repeat("x", 100),
	} {
		fragment := sources.Fragment{Raw: raw, StartLine: 1}
		want := original.detectFragment(t.Context(), fragment)
		require.Len(t, want, 1, raw)
		require.Equal(t, want, narrowed.detectFragment(t.Context(), fragment), raw)
	}
}
