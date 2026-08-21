package exprruntime

import "testing"

func TestContainsAnyCaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		terms []string
		want  bool
	}{
		{
			name:  "mixed-case input",
			input: "BearerTokenAuthorization",
			terms: []string{"authorization"},
			want:  true,
		},
		{
			name:  "mixed-case term",
			input: "bearertokenauthorization",
			terms: []string{"Authorization"},
			want:  true,
		},
		{
			name:  "no match",
			input: "BearerTokenAuthorization",
			terms: []string{"provider"},
			want:  false,
		},
		{
			name:  "unicode case folding",
			input: "CAFÉ_TOKEN",
			terms: []string{"fé_tok"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny(tt.input, tt.terms); got != tt.want {
				t.Errorf("containsAny(%q, %q) = %v, want %v", tt.input, tt.terms, got, tt.want)
			}
		})
	}
}

func TestContainsAnyExprListAndInvalidValues(t *testing.T) {
	if !containsAny("BearerTokenAuthorization", []any{"token", "provider"}) {
		t.Fatal("containsAny did not match a valid []any expression list")
	}
	if containsAny("BearerTokenAuthorization", []any{"token", 42}) {
		t.Fatal("containsAny accepted a non-string expression list")
	}
}

func TestContainsAnyASCIIAllocations(t *testing.T) {
	terms := []string{"authorization", "provider", "placeholder"}
	// Populate the immutable compiled-pattern cache before measuring the hot path.
	_ = containsAny("BearerTokenAuthorization", terms)
	allocs := testing.AllocsPerRun(100, func() {
		_ = containsAny("BearerTokenAuthorization", terms)
	})
	if allocs != 0 {
		t.Fatalf("containsAny allocated %.2f times per cached ASCII lookup", allocs)
	}
}
