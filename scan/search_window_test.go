package scan

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestSearchWindowsPreserveFindings(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			t.Parallel()
			pattern := `(?i)(?:key|keyword)[\w ]{0,3}[\s'"]{0,2}(?:=|:)(missing)?(?P<value>[a-z0-9]{8,})(?:;|$)`
			cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: pattern, Keywords: []string{"key", "keyword"}, ValueGroup: 2}}}
			narrowed := mustNew(t, cfg, WithRegexEngine(engine), WithMaxDecodeDepth(2), WithMatchContext("1L,20C"))
			original := mustNew(t, cfg, WithRegexEngine(engine), WithMaxDecodeDepth(2), WithMatchContext("1L,20C"))
			for i := range original.rulesBySpecificity {
				original.rulesBySpecificity[i].guard = nil
				original.rulesBySpecificity[i].span = nil
			}
			require.NotNil(t, narrowed.rulesBySpecificity[0].span)
			for _, value := range []string{
				"key=abcd1234;", "keyword=abcd1234;", "Key=abcd1234;", "key\n\t:abcd1234;",
				"key=missingabcd1234;", "key=abcd1234", "key=" + strings.Repeat("a", 8192) + ";",
				"key isn't assigned; keyword=abcd1234;", "key=abcd1234;key=efgh5678;",
			} {
				for depth := 0; depth <= 2; depth++ {
					raw := value
					for range depth {
						raw = base64.StdEncoding.EncodeToString([]byte(raw))
					}
					raw = strings.Repeat("filler, \xff😀\n", 100) + raw + "\n" + strings.Repeat("unrelated line\n", 100) + raw
					fragment := sources.Fragment{Raw: raw, StartLine: 41, Attributes: map[string]string{sources.AttrPath: "nested/test.txt"}}
					want := original.detectFragment(t.Context(), fragment)
					// The existing decoder accepts printable ASCII only.
					if depth > 0 && strings.IndexFunc(value, func(r rune) bool { return r > 127 }) >= 0 {
						require.Empty(t, want, "encoded Unicode is not decoded")
					} else {
						require.NotEmpty(t, want, "value %q depth %d", value, depth)
					}
					require.Equal(t, want, narrowed.detectFragment(t.Context(), fragment), "value %q depth %d", value, depth)
				}
			}
		})
	}
}

func TestSearchWindowsKeepComponentCoordinates(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `primary=([a-z]+)`, Keywords: []string{"primary"}, Components: []config.Component{{RuleID: "account", Within: "1L"}}},
		{ID: "account", Regex: `account=([a-z]+)`, Keywords: []string{"account"}, SkipReport: true},
	}}
	narrowed := mustNew(t, cfg, WithMaxDecodeDepth(2), WithMatchContext("1L,20C"))
	original := mustNew(t, cfg, WithMaxDecodeDepth(2), WithMatchContext("1L,20C"))
	for i := range original.rulesBySpecificity {
		original.rulesBySpecificity[i].span = nil
	}
	for depth := 0; depth <= 2; depth++ {
		value := "primary=secret account=identity"
		for range depth {
			value = base64.StdEncoding.EncodeToString([]byte(value))
		}
		raw := strings.Repeat("ordinary text\n", 200) + value + "\n" + strings.Repeat("other text\n", 200) + value
		fragment := sources.Fragment{Raw: raw, StartLine: 31}
		want := original.detectFragment(t.Context(), fragment)
		require.Len(t, want, 2)
		require.Equal(t, want, narrowed.detectFragment(t.Context(), fragment))
	}
}

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
