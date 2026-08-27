package config

import (
	"strings"
	"testing"
)

func TestComposeFilters(t *testing.T) {
	tests := []struct {
		name      string
		skipParts []string
		userExpr  string
		expected  string
	}{
		{name: "empty", expected: ""},
		{name: "user expression", userExpr: "condA", expected: "condA"},
		{name: "generated expression", skipParts: []string{"condA"}, expected: "condA"},
		{
			name:      "generated and user expressions",
			skipParts: []string{"condA", "condB"},
			userExpr:  "condC",
			expected:  "condA\n|| condB\n|| condC",
		},
		{
			name:      "user declaration",
			skipParts: []string{"condA"},
			userExpr:  "let context = finding.fragment_raw; context == secret",
			expected:  "condA\n|| (let context = finding.fragment_raw; context == secret)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := composeFilters(tt.skipParts, tt.userExpr); got != tt.expected {
				t.Fatalf("composeFilters() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestNormalizeRuleFilters(t *testing.T) {
	c := &Config{Rules: map[string]Rule{
		"entropy": {
			RuleID:  "entropy",
			Entropy: 3.5,
			Filter:  "existingFilter()",
		},
		"token-efficiency": {
			RuleID:          "token-efficiency",
			TokenEfficiency: true,
		},
		"integer-entropy": {
			RuleID:  "integer-entropy",
			Entropy: 4,
		},
	}}

	c.normalizeRuleFilters()

	entropyRule := c.Rules["entropy"]
	if !strings.Contains(entropyRule.Filter, `entropy(finding["secret"]) <= 3.5`) {
		t.Fatalf("entropy filter not normalized: %s", entropyRule.Filter)
	}
	if !strings.Contains(entropyRule.Filter, "existingFilter()") {
		t.Fatalf("existing filter lost: %s", entropyRule.Filter)
	}

	tokenRule := c.Rules["token-efficiency"]
	if !strings.Contains(tokenRule.Filter, `failsTokenEfficiency(finding["secret"])`) {
		t.Fatalf("token-efficiency filter not normalized: %s", tokenRule.Filter)
	}

	integerRule := c.Rules["integer-entropy"]
	if !strings.Contains(integerRule.Filter, `entropy(finding["secret"]) <= 4.0`) {
		t.Fatalf("integer entropy filter not normalized: %s", integerRule.Filter)
	}
}
