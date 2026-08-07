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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsAny(tt.input, tt.terms); got != tt.want {
				t.Errorf("containsAny(%q, %q) = %v, want %v", tt.input, tt.terms, got, tt.want)
			}
		})
	}
}
