package exprruntime

import "testing"

func TestContainsAnyCaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input any
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
			name:  "list match",
			input: []any{"read_repository", "write_registry"},
			terms: []string{"registry"},
			want:  true,
		},
		{
			name:  "list without match",
			input: []string{"read_repository", "write_registry"},
			terms: []string{"runner"},
			want:  false,
		},
		{
			name:  "mixed-type list",
			input: []any{"read_repository", 42},
			terms: []string{"repository"},
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

func TestMatchesAnyStringOrList(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		patterns []string
		want     bool
	}{
		{name: "string", input: "read_repository", patterns: []string{"^read_"}, want: true},
		{name: "list match", input: []any{"granular", "write_repository"}, patterns: []string{"^write_"}, want: true},
		{name: "list without match", input: []string{"granular", "self_rotate"}, patterns: []string{"^write_"}, want: false},
		{name: "mixed-type list", input: []any{"write_repository", 42}, patterns: []string{"^write_"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchesAny(tt.input, tt.patterns)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("matchesAny(%v, %q) = %v, want %v", tt.input, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestMatchesAnyRejectsInvalidPattern(t *testing.T) {
	_, err := matchesAny("read_repository", []string{"*read"})
	if err == nil {
		t.Fatal("matchesAny accepted an invalid regular expression")
	}
}

func TestStartsWithAnyStringOrList(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		prefixes []string
		want     bool
	}{
		{name: "string", input: "read_repository", prefixes: []string{"read_", "write_"}, want: true},
		{name: "list match", input: []any{"granular", "create_email"}, prefixes: []string{"create_"}, want: true},
		{name: "prefix must be leading", input: []string{"future_read_permission"}, prefixes: []string{"read_"}, want: false},
		{name: "mixed-type list", input: []any{"read_repository", 42}, prefixes: []string{"read_"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startsWithAny(tt.input, tt.prefixes); got != tt.want {
				t.Errorf("startsWithAny(%v, %q) = %v, want %v", tt.input, tt.prefixes, got, tt.want)
			}
		})
	}
}

func TestIntersectsStringOrList(t *testing.T) {
	tests := []struct {
		name       string
		values     any
		candidates any
		want       bool
	}{
		{name: "string", values: "api", candidates: []string{"api", "sudo"}, want: true},
		{name: "list match", values: []any{"read_api", "write_repository"}, candidates: []string{"write_repository"}, want: true},
		{name: "exact", values: []string{"read_api"}, candidates: []string{"read"}, want: false},
		{name: "mixed values", values: []any{"read_api", 42}, candidates: []string{"read_api"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := intersects(tt.values, tt.candidates); got != tt.want {
				t.Errorf("intersects(%v, %v) = %v, want %v", tt.values, tt.candidates, got, tt.want)
			}
		})
	}
}
