package generic

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// testConfig returns the global policy with the generic rules ids, in order.
// Only this package's rules are registered in its tests.
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
