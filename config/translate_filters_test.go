package config

import (
	"strings"
	"testing"
)

func TestCelStringLit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "contains backslash (safe for raw string)",
			input:    `\d{4}-\d{2}-\d{2}`,
			expected: `r"""\d{4}-\d{2}-\d{2}"""`,
		},
		{
			name:     "contains double quote",
			input:    `my "secret"`,
			expected: `"my \"secret\""`,
		},
		{
			name:     "contains newline and tab",
			input:    "line1\n\tline2",
			expected: `"line1\n\tline2"`,
		},
		{
			name:     "contains triple quote (no backslash)",
			input:    `"""`,
			expected: `"\"\"\""`,
		},
		{
			name:     "contains triple quote AND backslash (the edge case)",
			input:    `(?i)secret"""\s*=\s*\w+`,
			expected: `"(?i)secret\"\"\"\\s*=\\s*\\w+"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := celStringLit(tt.input)
			if actual != tt.expected {
				t.Errorf("celStringLit() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestCelStringList(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "empty list",
			input:    []string{},
			expected: "[]",
		},
		{
			name:     "single item",
			input:    []string{"hello"},
			expected: `["hello"]`,
		},
		{
			name:     "single regex item",
			input:    []string{`\d+`},
			expected: `[r"""\d+"""]`,
		},
		{
			name:  "multiple items (multiline formatting)",
			input: []string{"a", `\b`, "c"},
			expected: `[
  "a",
  r"""\b""",
  "c"
]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := celStringList(tt.input)
			if actual != tt.expected {
				t.Errorf("celStringList() = \n%v\nwant \n%v", actual, tt.expected)
			}
		})
	}
}

func TestComposeFilters(t *testing.T) {
	tests := []struct {
		name      string
		skipParts []string
		userExpr  string
		expected  string
	}{
		{
			name:      "empty inputs",
			skipParts: nil,
			userExpr:  "",
			expected:  "",
		},
		{
			name:      "only user expr",
			skipParts: nil,
			userExpr:  "has(finding.secret)",
			expected:  "(has(finding.secret))",
		},
		{
			name:      "one skip part, no user expr",
			skipParts: []string{"matchesAny(path, [...])"},
			userExpr:  "",
			expected:  "(matchesAny(path, [...]))",
		},
		{
			name:      "multiple skip parts",
			skipParts: []string{"condA", "condB"},
			userExpr:  "",
			expected:  "(condA)\n|| (condB)",
		},
		{
			name:      "skip parts and user expr",
			skipParts: []string{"condA", "condB"},
			userExpr:  "condC",
			expected:  "(condA)\n|| (condB)\n|| (condC)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := composeFilters(tt.skipParts, tt.userExpr)
			if actual != tt.expected {
				t.Errorf("composeFilters() = %q, want %q", actual, tt.expected)
			}
		})
	}
}

func TestTranslateLegacyFilters(t *testing.T) {
	c := &Config{
		Rules: map[string]Rule{
			"rule-1": {
				RuleID:  "rule-1",
				Entropy: 3.5,
				Filter:  "existing_filter()",
			},
			"rule-2": {
				RuleID:          "rule-2",
				TokenEfficiency: true,
			},
			"rule-3": {
				RuleID:  "rule-3",
				Entropy: 4, // Integer edge case for formatting
			},
		},
	}

	err := c.TranslateLegacyFilters()
	if err != nil {
		t.Fatalf("TranslateLegacyFilters returned error: %v", err)
	}

	r1 := c.Rules["rule-1"]
	if !strings.Contains(r1.Filter, `entropy(finding["secret"]) <= 3.5`) {
		t.Errorf("rule-1 missing entropy filter: %s", r1.Filter)
	}
	if !strings.Contains(r1.Filter, `existing_filter()`) {
		t.Errorf("rule-1 missing existing filter: %s", r1.Filter)
	}

	r2 := c.Rules["rule-2"]
	if !strings.Contains(r2.Filter, `!tokenEfficiencyOK`) {
		t.Errorf("rule-2 missing token efficiency filter: %s", r2.Filter)
	}

	r3 := c.Rules["rule-3"]
	if !strings.Contains(r3.Filter, `entropy(finding["secret"]) <= 4.0`) {
		t.Errorf("rule-3 missing formatted integer entropy filter: %s", r3.Filter)
	}
}
