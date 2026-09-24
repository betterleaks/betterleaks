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

func TestRuleValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
		want string
	}{
		{"negative group", Rule{ID: "test", Regex: `(secret)`, SecretGroup: -1}, "must be non-negative"},
		{"group without regex", Rule{ID: "test", Path: `\.env$`, SecretGroup: 1}, "requires a regex"},
		{"capture overflow", Rule{ID: "test", Regex: `(?P<secret>secret)`, SecretGroup: 2}, "max regex secret group 1"},
		{"invalid regex", Rule{ID: "test", Regex: `(`}, "invalid regex"},
		{"invalid path", Rule{ID: "test", Path: `[`}, "invalid path regex"},
		{"analysis without validation", Rule{ID: "test", Regex: `secret`, AnalyzeExpr: `{}`}, "analyze expression requires a validate expression"},
		{"analysis with validation", Rule{ID: "test", Regex: `secret`, ValidateExpr: `{"result":"valid"}`, AnalyzeExpr: `{}`}, ""},
		{"path validation", Rule{ID: "path", Path: `\.env$`, ValidateExpr: `{"result":"valid"}`}, "path-only rules cannot"},
		{"path components", Rule{ID: "path", Path: `\.env$`, Components: []Component{{RuleID: "part"}}}, "path-only rules cannot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.rule
			err := tc.rule.Validate()
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.want)
			}
			require.Equal(t, original, tc.rule, "validation must not mutate the rule")
		})
	}
}

func TestConfigValidateRejectsAmbiguousRuleGraph(t *testing.T) {
	validRegex := `secret`
	tests := []struct {
		name  string
		rules []Rule
		want  string
	}{
		{
			name: "nested components",
			rules: []Rule{
				{ID: "a", Regex: "AAA", Components: []Component{{RuleID: "b"}}},
				{ID: "b", Regex: "BBB", Components: []Component{{RuleID: "c"}}},
				{ID: "c", Regex: "CCC"},
			},
			want: "must not itself have components",
		},
		{
			name: "component cycle",
			rules: []Rule{
				{ID: "a", Regex: "AAA", Components: []Component{{RuleID: "b"}}},
				{ID: "b", Regex: "BBB", Components: []Component{{RuleID: "c"}}},
				{ID: "c", Regex: "CCC", Components: []Component{{RuleID: "a"}}},
			},
			want: "must not itself have components",
		},
		{
			name: "path-only component",
			rules: []Rule{
				{ID: "primary", Regex: "TOKEN", Components: []Component{{RuleID: "path"}}},
				{ID: "path", Path: `\.env$`},
			},
			want: "cannot be a credential component",
		},
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
				{ID: "primary", Regex: validRegex, Components: []Component{{RuleID: "missing"}}},
			},
			want: `component rule ID "missing" does not exist`,
		},
		{
			name: "self component",
			rules: []Rule{
				{ID: "primary", Regex: validRegex, Components: []Component{{RuleID: "primary"}}},
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

func TestParseRejectsInvalidRules(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"duplicate ID", `[[rules]]
id = "duplicate"
description = "first"
regex = "first"
[[rules]]
id = "duplicate"
description = "second"
regex = "second"
`, `duplicate rule ID "duplicate"`},
		{"invalid pattern", `[[rules]]
id = "invalid"
regex = "("
[[rules]]
id = "valid"
regex = "valid"
`, "invalid regex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTOMLString(tc.input, "")
			require.ErrorContains(t, err, tc.want)
		})
	}
}
