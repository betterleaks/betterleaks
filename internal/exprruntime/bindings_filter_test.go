package exprruntime

import (
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/stretchr/testify/require"
)

func TestCompiledAttributeMatchPreservesPrefilterSemantics(t *testing.T) {
	for _, test := range []struct {
		expression string
		compiled   bool
	}{
		{`matchesAny(attributes["path"], ["(?i)\\.png$", "(?:^|/)vendor/"])`, true},
		{`matchesAny(attributes.path, ["^$", "secret"])`, true},
		{`matchesAny(attributes.commit, ["abc"])`, true},
		{`matchesAny(attributes.path, [])`, false},
		{`matchesAny(attributes.path, ["secret", 42])`, true},
		{`matchesAny(attributes.path, ["["])`, false},
		{`matchesAny(attributes.path, [attributes.pattern])`, false},
		{`matchesAny([attributes.path], ["secret"])`, false},
		{`matchesAny(attributes.path, ["secret"]) || attributes.keep == "no"`, false},
		{`let path = attributes.path; matchesAny(path, ["secret"])`, false},
	} {
		t.Run(test.expression, func(t *testing.T) {
			runtime := NewLocal(nil)
			program, err := runtime.CompilePrefilter(test.expression)
			require.NoError(t, err)
			require.Equal(t, test.compiled, program.attributeMatch != nil)
			interpreted := *program
			interpreted.attributeMatch = nil
			for _, attrs := range []map[string]string{
				nil, {}, {"path": ""}, {"path": "photo.PNG"}, {"path": "vendor/code.go"},
				{"path": "secret", "pattern": "secret"}, {"commit": "abc", "keep": "no"},
				{"path": "public", "pattern": "["}, {"path": "秘密/é.txt"},
			} {
				want, wantErr := runtime.EvalPrefilter(&interpreted, attrs)
				got, gotErr := runtime.EvalPrefilter(program, attrs)
				require.Equal(t, want, got, "attributes: %v", attrs)
				if wantErr != nil {
					require.EqualError(t, gotErr, wantErr.Error())
				} else {
					require.NoError(t, gotErr)
				}
			}
		})
	}
}

func TestCompiledAttributeMatchIsConcurrent(t *testing.T) {
	runtime := NewLocal(nil)
	program, err := runtime.CompilePrefilter(`matchesAny(attributes.path, ["^skip$"])`)
	require.NoError(t, err)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				for _, path := range []string{"skip", "keep"} {
					got, err := runtime.EvalPrefilter(program, map[string]string{"path": path})
					if err != nil || got != (path == "skip") {
						t.Errorf("path=%s: result=%t error=%v", path, got, err)
					}
				}
			}
		})
	}
	workers.Wait()
}

func BenchmarkPrefilterAttributeMatch(b *testing.B) {
	for _, engine := range []blregexp.Engine{blregexp.Stdlib{}, re2.RE2{}} {
		b.Run(engine.Version(), func(b *testing.B) {
			runtime := NewLocal(engine)
			program, err := runtime.CompilePrefilter(`matchesAny(attributes.path, ["(?i)\\.png$", "(?:^|/)vendor/", "(?:^|/)node_modules/"])`)
			require.NoError(b, err)
			attrs := map[string]string{"path": "project/src/main.go"}
			for _, compiled := range []bool{false, true} {
				name := "vm"
				if compiled {
					name = "compiled"
				}
				b.Run(name, func(b *testing.B) {
					prg := *program
					if !compiled {
						prg.attributeMatch = nil
					}
					_, err := runtime.EvalPrefilter(&prg, attrs)
					require.NoError(b, err)
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						_, _ = runtime.EvalPrefilter(&prg, attrs)
					}
				})
			}
		})
	}
}

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
			got, err := new(Runtime).matchesAny(tt.input, tt.patterns)
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
	_, err := new(Runtime).matchesAny("read_repository", []string{"*read"})
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

func TestTokenEfficiencyBindings(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	counter, err := tokenizer.Default()
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		secret string
		expr   string
		want   bool
	}{
		{
			name:   "wordlist-assisted check",
			secret: "linkedinX9qB2mK7pR4zT8",
			expr:   `failsTokenEfficiency(finding["secret"])`,
			want:   true,
		},
		{
			name:   "ratio-only check",
			secret: "linkedinX9qB2mK7pR4zT8",
			expr:   `tokenRatio(finding["secret"]) >= 2.5`,
			want:   false,
		},
		{
			name:   "readable placeholder ratio",
			secret: "this-is-a-long-readable-placeholder-value",
			expr:   `tokenRatio(finding["secret"]) >= 2.5`,
			want:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prg, err := env.CompileFilter(tc.expr, counter)
			require.NoError(t, err)

			got, err := env.EvalFilter(prg, map[string]any{"secret": tc.secret}, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
