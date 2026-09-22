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
			cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: pattern, Keywords: []string{"key", "keyword"}, SecretGroup: 2}}}
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
