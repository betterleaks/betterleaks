package config

import (
	"strings"
	"testing"
)

func TestCelRegexLit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple regex without backslashes",
			input:    `^[a-zA-Z_.-]+$`,
			expected: `r"""^[a-zA-Z_.-]+$"""`,
		},
		{
			name:     "contains backslash",
			input:    `\d{4}-\d{2}-\d{2}`,
			expected: `r"""\d{4}-\d{2}-\d{2}"""`,
		},
		{
			name:     "contains triple quote (fallback to strconv.Quote)",
			input:    `(?i)secret"""\s*=\s*\w+`,
			expected: `"(?i)secret\"\"\"\\s*=\\s*\\w+"`,
		},
		{
			name:     "backslash pattern ending in quote (#140 repro)",
			input:    `(?im)"@[\w\/]+":[ ]{0,20}"[\w\.\-\d]+"`,
			expected: `"(?im)\"@[\\w\\/]+\":[ ]{0,20}\"[\\w\\.\\-\\d]+\""`,
		},
		{
			name:     "quotes in middle are fine with raw strings",
			input:    `['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`,
			expected: `r"""['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?"""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := celRegexLit(tt.input)
			if actual != tt.expected {
				t.Errorf("celRegexLit() = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestCelStringLit(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain string",
			input:    "secret",
			expected: `"secret"`,
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

func TestCelRegexList(t *testing.T) {
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
			input:    []string{`\d+`},
			expected: `[r"""\d+"""]`,
		},
		{
			name:  "multiple items (multiline formatting)",
			input: []string{"^foo$", `\b`, "^bar$"},
			expected: `[
  r"""^foo$""",
  r"""\b""",
  r"""^bar$"""
]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := celRegexList(tt.input)
			if actual != tt.expected {
				t.Errorf("celRegexList() = \n%v\nwant \n%v", actual, tt.expected)
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
			name:  "multiple items (multiline formatting)",
			input: []string{"a", "b", "c"},
			expected: `[
  "a",
  "b",
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
			expected:  "has(finding.secret)",
		},
		{
			name:      "one skip part, no user expr",
			skipParts: []string{"matchesAny(path, [...])"},
			userExpr:  "",
			expected:  "matchesAny(path, [...])",
		},
		{
			name:      "multiple skip parts",
			skipParts: []string{"condA", "condB"},
			userExpr:  "",
			expected:  "condA\n|| condB",
		},
		{
			name:      "skip parts and user expr",
			skipParts: []string{"condA", "condB"},
			userExpr:  "condC",
			expected:  "condA\n|| condB\n|| condC",
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
	if !strings.Contains(r2.Filter, `failsTokenEfficiency`) {
		t.Errorf("rule-2 missing token efficiency filter: %s", r2.Filter)
	}

	r3 := c.Rules["rule-3"]
	if !strings.Contains(r3.Filter, `entropy(finding["secret"]) <= 4.0`) {
		t.Errorf("rule-3 missing formatted integer entropy filter: %s", r3.Filter)
	}
}
