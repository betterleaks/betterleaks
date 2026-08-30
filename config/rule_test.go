package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/regexp"
)

func TestRuleValidateRechecksCurrentData(t *testing.T) {
	rule := Rule{RuleID: "test", Regex: regexp.MustCompile(`secret`)}
	require.NoError(t, rule.Validate())

	rule.RuleID = ""
	require.ErrorContains(t, rule.Validate(), "|id| is missing or empty")
}

func TestRuleValidateRejectsInvalidSecretGroups(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{
			name: "negative",
			rule: Rule{RuleID: "test", Regex: regexp.MustCompile(`(secret)`), SecretGroup: -1},
			want: "must be non-negative",
		},
		{
			name: "without regex",
			rule: Rule{RuleID: "test", Path: regexp.MustCompile(`\.env$`), SecretGroup: 1},
			want: "requires a regex",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, test.rule.Validate(), test.want)
		})
	}
}

func TestConfigValidateRejectsAmbiguousRuleGraph(t *testing.T) {
	validRegex := regexp.MustCompile(`secret`)
	tests := []struct {
		name  string
		rules []Rule
		want  string
	}{
		{
			name: "duplicate rule ID",
			rules: []Rule{
				{RuleID: "duplicate", Regex: validRegex},
				{RuleID: "duplicate", Regex: validRegex},
			},
			want: `duplicate rule ID "duplicate"`,
		},
		{
			name: "missing component",
			rules: []Rule{
				{RuleID: "primary", Regex: validRegex, Components: []*Component{{RuleID: "missing"}}},
			},
			want: `component rule ID "missing" does not exist`,
		},
		{
			name: "self component",
			rules: []Rule{
				{RuleID: "primary", Regex: validRegex, Components: []*Component{{RuleID: "primary"}}},
			},
			want: "cannot reference itself",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{Rules: test.rules}
			require.ErrorContains(t, cfg.Validate(), test.want)
		})
	}
}

func TestParseDuplicateRuleIDKeepsLastDefinition(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "duplicate"
description = "first"
regex = "first"

[[rules]]
id = "duplicate"
description = "second"
regex = "second"
`, "")
	require.NoError(t, err)
	require.Len(t, cfg.Rules, 1)
	require.Equal(t, "second", cfg.Rules[0].Description)
	require.Equal(t, "second", cfg.Rules[0].Regex.String())
}
