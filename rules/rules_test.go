package rules

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
	"github.com/betterleaks/betterleaks/v2/internal/ruletest"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/scan"
)

var engines = []regexp.Engine{regexp.Stdlib{}, re2.RE2{}}

// TestRules runs every rule's tests. Focus on one provider with:
//
//	go test ./rules -run TestRules/acme
func TestRules(t *testing.T) {
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	runners := make([]*ruletest.Runner, len(engines))
	for i, engine := range engines {
		runners[i], err = ruletest.New(cfg, engine)
		require.NoError(t, err)
	}
	for _, rule := range cfg.Rules {
		t.Run(rule.ID, func(t *testing.T) {
			for i, engine := range engines {
				failures, err := runners[i].Run(t.Context(), rule)
				require.NoError(t, err)
				for _, failure := range failures {
					t.Errorf("%s: %s test %q: %v", rulebuilder.File(rule.ID), engine.Version(), failure.Test, failure.Err)
				}
			}
		})
	}
}

// TestCompile checks every regex and provider expression, including rules
// without tests.
func TestCompile(t *testing.T) {
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	for _, engine := range engines {
		_, err := scan.New(cfg, scan.WithRegexEngine(engine), scan.WithPrecompile())
		require.NoError(t, err, engine.Version())
	}
	_, err = analyze.New(cfg, analyze.WithPrecompile())
	require.NoError(t, err)
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	for _, rule := range cfg.Rules {
		if rule.RevokeExpr != "" {
			_, err := runtime.CompileRevocation(rule.RevokeExpr)
			require.NoError(t, err, rule.ID)
		}
	}
}

// testConfig returns the default config narrowed to the rules ids, in order.
func testConfig(t testing.TB, ids ...string) *config.Config {
	t.Helper()
	cfg, err := rulebuilder.Config()
	require.NoError(t, err)
	rules := cfg.Rules
	cfg.Rules = nil
	for _, id := range ids {
		i := slices.IndexFunc(rules, func(rule config.Rule) bool { return rule.ID == id })
		require.NotEqual(t, -1, i, "no registered rule %q", id)
		cfg.Rules = append(cfg.Rules, rules[i])
	}
	return cfg
}

// testRule returns a copy of a registered rule.
func testRule(t testing.TB, id string) *config.Rule {
	t.Helper()
	return &testConfig(t, id).Rules[0]
}
