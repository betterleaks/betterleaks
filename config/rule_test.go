package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleValidateRechecksCurrentData(t *testing.T) {
	rule := Rule{ID: "test", Regex: `secret`}
	require.NoError(t, rule.Validate())

	rule.ID = ""
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
			rule: Rule{ID: "test", Regex: `(secret)`, SecretGroup: -1},
			want: "must be non-negative",
		},
		{
			name: "without regex",
			rule: Rule{ID: "test", Path: `\.env$`, SecretGroup: 1},
			want: "requires a regex",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, test.rule.Validate(), test.want)
		})
	}
}

func TestRuleValidateRequiresValidationForAnalysis(t *testing.T) {
	rule := Rule{
		ID:          "test",
		Regex:       `secret`,
		AnalyzeExpr: `{}`,
	}
	require.ErrorContains(t, rule.Validate(), "analyze expression requires a validate expression")

	rule.ValidateExpr = `{"result": "valid"}`
	require.NoError(t, rule.Validate())
}

func TestConfigValidateRejectsAmbiguousRuleGraph(t *testing.T) {
	validRegex := `secret`
	tests := []struct {
		name  string
		rules []Rule
		want  string
	}{
		{
			name: "duplicate rule ID",
			rules: []Rule{
				{ID: "duplicate", Regex: validRegex},
				{ID: "duplicate", Regex: validRegex},
			},
			want: `duplicate rule ID "duplicate"`,
		},
		{
			name: "missing component",
			rules: []Rule{
				{ID: "primary", Regex: validRegex, Components: []*Component{{RuleID: "missing"}}},
			},
			want: `component rule ID "missing" does not exist`,
		},
		{
			name: "self component",
			rules: []Rule{
				{ID: "primary", Regex: validRegex, Components: []*Component{{RuleID: "primary"}}},
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
	require.Equal(t, "second", cfg.Rules[0].Regex)
}

func TestRuleValidatePatternStrings(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		want string
	}{
		{"invalid regex", Rule{ID: "test", Regex: `(`}, "invalid regex"},
		{"invalid path", Rule{ID: "test", Path: `[`}, "invalid path regex"},
		{"capture overflow", Rule{ID: "test", Regex: `(?P<secret>secret)`, SecretGroup: 2}, "max regex secret group 1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := test.rule
			require.ErrorContains(t, test.rule.Validate(), test.want)
			require.Equal(t, original, test.rule)
		})
	}
}

func TestParseRejectsInvalidPatternBeforeDuplicateReplacement(t *testing.T) {
	_, err := ParseTOMLString(`
[[rules]]
id = "duplicate"
regex = "("
[[rules]]
id = "duplicate"
regex = "valid"
`, "")
	require.ErrorContains(t, err, "invalid regex")
}
