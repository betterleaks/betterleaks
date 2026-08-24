package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/regexp"
)

func TestRuleValidateAlwaysChecksCurrentState(t *testing.T) {
	rule := Rule{RuleID: "test", Regex: regexp.MustCompile("secret")}
	require.NoError(t, rule.Validate())

	rule.RuleID = ""
	require.ErrorContains(t, rule.Validate(), "rule |id| is missing or empty")
}

func TestRuleValidateRejectsNilRule(t *testing.T) {
	var rule *Rule
	require.EqualError(t, rule.Validate(), "rule is required")
}

func TestRuleValidateRejectsInvalidSecretGroup(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		rule := Rule{RuleID: "test", Regex: regexp.MustCompile("(secret)"), SecretGroup: -1}
		require.EqualError(t, rule.Validate(), "test: invalid regex secret group -1, must be non-negative")
	})

	t.Run("without regex", func(t *testing.T) {
		rule := Rule{RuleID: "test", Path: regexp.MustCompile("secret"), SecretGroup: 1}
		require.EqualError(t, rule.Validate(), "test: regex secret group 1 requires a regex")
	})
}

func TestRuleValidateRejectsSelfComponent(t *testing.T) {
	rule := Rule{
		RuleID:     "test",
		Regex:      regexp.MustCompile("secret"),
		Components: []*Component{{RuleID: "test"}},
	}
	require.EqualError(t, rule.Validate(), "test: rule cannot reference itself as a component")
}
