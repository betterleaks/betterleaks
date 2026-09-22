package scan

import (
	"encoding/base64"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestPrefixWindowsPreserveEligibility(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			t.Parallel()
			pattern := `(?i)(?:password=[a-z]{5,}|(?:login|log_in|authenticate)[ \t]*\([ \t]*[a-z]+,[ \t]*"([a-z]{4,})"[ \t]*\))`
			cfg := &config.Config{Rules: []config.Rule{{ID: "password", Regex: pattern, Keywords: []string{"password", "login(", "login (", "log_in(", "log_in (", "authenticate(", "authenticate ("}}}}
			narrowed := mustNew(t, cfg, WithRegexEngine(engine), WithMaxDecodeDepth(2), WithMatchContext("2L,20C"))
			original := mustNew(t, cfg, WithRegexEngine(engine), WithMaxDecodeDepth(2), WithMatchContext("2L,20C"))
			for i := range original.rulesBySpecificity {
				original.rulesBySpecificity[i].span = nil
				original.rulesBySpecificity[i].searchAnchors = nil
			}
			clear(original.anchorRuleIndexes)
			require.NotNil(t, narrowed.rulesBySpecificity[0].searchAnchors)
			for _, tc := range []struct {
				raw   string
				count int
			}{
				{`login   (user,"hunter")`, 0},
				{"password keyword\nlogin   (user,\"hunter\")", 1},
				{"password keyword\nauthenticate\t\t(user,\"hunter\")", 1},
				{"login(user,\"hunter\")\n" + strings.Repeat("ordinary text\n", 100) + "log_in   (user,\"longsecret\")", 2},
				{"password keyword\nlogin" + strings.Repeat(" ", 16384) + "(user,\"hunter\")", 1},
				{"password keyword\nlogin\n(user,\"hunter\")", 0},
				{"paſſword=secret", 1},
			} {
				for depth := 0; depth <= 2; depth++ {
					raw := tc.raw
					for range depth {
						raw = base64.StdEncoding.EncodeToString([]byte(raw))
					}
					fragment := sources.Fragment{Raw: raw, StartLine: 31, Attributes: map[string]string{sources.AttrPath: "nested/test.txt"}}
					want := original.detectFragment(t.Context(), fragment)
					count := tc.count
					// Preserve the decoder's existing ASCII-only output contract.
					if depth > 0 && strings.IndexFunc(tc.raw, func(r rune) bool { return r > 127 }) >= 0 {
						count = 0
					}
					require.Len(t, want, count, "input %q depth %d", tc.raw, depth)
					require.Equal(t, want, narrowed.detectFragment(t.Context(), fragment), "depth %d", depth)
				}
			}
		})
	}
}

func FuzzSearchAnchorEligibility(f *testing.F) {
	cfg := &config.Config{Rules: []config.Rule{{
		ID: "password", Regex: `(?i)(?:passw[a-z]{0,5}=[a-z]{5,}|(?:login|log_in)[ \t]*\([a-z]+,[ \t]*"([a-z]{4,})"\))`,
		Keywords: []string{"passw", "login(", "login (", "log_in(", "log_in ("},
	}}}
	narrowed, err := New(cfg, WithMaxDecodeDepth(2), WithMatchContext("2L,20C"))
	if err != nil {
		f.Fatal(err)
	}
	original, err := New(cfg, WithMaxDecodeDepth(2), WithMatchContext("2L,20C"))
	if err != nil {
		f.Fatal(err)
	}
	for i := range original.rulesBySpecificity {
		original.rulesBySpecificity[i].guard = nil
		original.rulesBySpecificity[i].span = nil
		original.rulesBySpecificity[i].searchAnchors = nil
	}
	clear(original.anchorRuleIndexes)
	for _, seed := range []string{
		"", `login   (user,"hunter")`, "passw\nlogin   (user,\"hunter\")",
		`login(user,"hunter") log_in    (user,"othersecret")`, "paſſword=secret", "\xffpassw=other",
		base64.StdEncoding.EncodeToString([]byte("passw\nlogin   (user,\"hunter\")")),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16000 {
			return
		}
		fragment := sources.Fragment{Raw: raw, StartLine: 31}
		want := original.detectFragment(t.Context(), fragment)
		got := narrowed.detectFragment(t.Context(), fragment)
		require.Equal(t, want, got)
	})
}
