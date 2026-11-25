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
		// A literal holding one keyword splits around it.
		{`mytoken=([a-z]{10})`, true},
		// With two keywords, windows may be measured from the other one.
		{`tokensecret=([a-z]{10})`, false},
		// A literal before the keyword element could hold a keyword itself.
		{`secretx(?:token)=([a-z]{10})`, false},
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
	for _, tc := range []struct {
		raw    string
		accept bool
	}{
		{"def access_level_for(user)", false},
		{"user.token_count + 1", false},
		{"api_key = 'Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB'", true},
		{`"credential": {"value": "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"}`, true},
		{"<cfg:API_KEYS>\n<site>Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB</site>", true},
		{"secret\n\t= Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB", true},
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
