package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestComponentGraphMustBeFlat(t *testing.T) {
	cfg := &Config{Rules: []Rule{
		{ID: "a", Regex: `AAA`, Components: []Component{{RuleID: "b"}}},
		{ID: "b", Regex: `BBB`, Components: []Component{{RuleID: "c"}}},
		{ID: "c", Regex: `CCC`, Components: []Component{{RuleID: "a"}}},
	}}
	require.ErrorContains(t, cfg.Validate(), "must not itself have components")
	cfg.Rules[2].Components = nil
	require.ErrorContains(t, cfg.Validate(), "must not itself have components")
}

func TestPathRulesCannotResolveCredentials(t *testing.T) {
	for _, rule := range []Rule{
		{ID: "path", Path: `\.env$`, ValidateExpr: `{"result":"valid"}`},
		{ID: "path", Path: `\.env$`, Components: []Component{{RuleID: "part"}}},
	} {
		require.ErrorContains(t, rule.Validate(), "path-only rules cannot")
	}
	cfg := &Config{Rules: []Rule{{ID: "primary", Regex: `TOKEN`, Components: []Component{{RuleID: "path"}}}, {ID: "path", Path: `\.env$`}}}
	require.ErrorContains(t, cfg.Validate(), "cannot be a credential component")
}
