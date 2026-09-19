package scan

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/lucasjones/reggen"
)

func TestAssignmentGuardProof(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		valid   bool
	}{
		{`token[\w ]{0,20}[\s'"]{0,3}(?:=|:|=>)([a-z]{10})`, true},
		{`tokenSuffix[\w ]{0,20}[\s'"]{0,3}=([a-z]{10})`, false},
		{`(?:token|other)[\w ]{0,20}[\s'"]{0,3}=([a-z]{10})`, false},
		{`token[\w =]{0,20}[\s'"]{0,3}=([a-z]{10})`, false},
		{`token[\w ]{0,20}[\s'"]{0,3}(?:=)?([a-z]{10})`, false},
		{`token[\w ]*[\s'"]{0,3}=([a-z]{10})`, false},
		{`.*token[\w ]{0,20}[\s'"]{0,3}=([a-z]{10})`, false},
		{`token[\w ]{0,20}[\s'"]{0,3}(?:=|)([a-z]{10})`, false},
		{`(?:token|)[\w ]{0,20}[\s'"]{0,3}=([a-z]{10})`, false},
	} {
		parsed, err := syntax.Parse(tc.pattern, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if got := inferAssignmentGuard(parsed, []string{"ToKeN"}) != nil; got != tc.valid {
			t.Fatalf("%s: got %v want %v", tc.pattern, got, tc.valid)
		}
	}
}

func guardAccepts(guard *assignmentGuard, matcher *ahocorasick.Matcher, raw string) bool {
	accepted := false
	matcher.Visit(raw, func(_, _, end int) bool {
		if guard.possible(raw, end) {
			accepted = true
			return false
		}
		return true
	})
	return accepted
}

func TestDefaultAssignmentGuards(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	generic := false
	for _, rule := range cfg.Rules {
		guard := compileAssignmentGuard(rule.Regex, rule.Keywords)
		if guard == nil {
			continue
		}
		if rule.ID == "generic-api-key" {
			generic = true
		}
		t.Run(rule.ID, func(t *testing.T) {
			matcher := ahocorasick.Compile(rule.Keywords, true)
			original := regexp.MustCompile(rule.Regex)
			for _, keyword := range rule.Keywords {
				for _, key := range []string{keyword, strings.ToUpper(keyword), strings.ReplaceAll(strings.ReplaceAll(keyword, "s", "ſ"), "k", "K")} {
					for _, identifier := range []string{"", "_name", strings.Repeat("a", 20), strings.Repeat("a", 21), strings.Repeat("K", 20), "\xff"} {
						for _, padding := range []string{"", "'\n\t", "'\n\t\t", strings.Repeat(" ", 23), "😀"} {
							for _, op := range []string{"=", "=>", ":=", ":::=", "||", "?=", ",", ">", ":", "not an assignment"} {
								raw := "unrelated text\n" + key + identifier + padding + op + "'aZ8vQ2xR9mN6pL3t'\n"
								if original.MatchString(raw) && !guardAccepts(guard, matcher, raw) {
									t.Fatalf("guard omitted a regex match in %q", raw)
								}
							}
						}
					}
				}
			}
		})
	}
	if !generic {
		t.Fatal("generic rule has no guard")
	}
}

func TestAssignmentGuardRejectsNonAssignments(t *testing.T) {
	pattern := `(?i)token[\w ]{0,20}[\s'"]{0,3}=([a-z]{10})`
	guard := compileAssignmentGuard(pattern, []string{"token"})
	matcher := ahocorasick.Compile([]string{"token"}, true)
	for _, raw := range []string{"token isn't assigned", "token\n\n\n\n=abcdefghij", "token" + strings.Repeat("x", 21) + "=abcdefghij"} {
		if guardAccepts(guard, matcher, raw) {
			t.Errorf("unnecessary candidate %q", raw)
		}
	}
	// Later keyword hits must still be considered after an earlier rejection.
	if !guardAccepts(guard, matcher, "token isn't assigned; token=abcdefghij") {
		t.Fatal("later assignment rejected")
	}
}

func TestAssignmentGuardGeneratedMatches(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range cfg.Rules {
		guard := compileAssignmentGuard(rule.Regex, rule.Keywords)
		if guard == nil {
			continue
		}
		t.Run(rule.ID, func(t *testing.T) {
			generator, err := reggen.NewGenerator(rule.Regex)
			if err != nil {
				t.Fatal(err)
			}
			generator.SetSeed(1)
			matcher := ahocorasick.Compile(rule.Keywords, true)
			original := regexp.MustCompile(rule.Regex)
			for range 100 {
				raw := "ordinary text\n" + generator.Generate(32) + "\nmore text"
				if original.MatchString(raw) && !guardAccepts(guard, matcher, raw) {
					t.Fatalf("guard omitted a generated regex match in %q", raw)
				}
			}
		})
	}
}

func FuzzAssignmentGuard(f *testing.F) {
	cfg, err := config.Default()
	if err != nil {
		f.Fatal(err)
	}
	rule, ok := cfg.Rule("generic-api-key")
	if !ok {
		f.Fatal("missing generic rule")
	}
	guard := compileAssignmentGuard(rule.Regex, rule.Keywords)
	matcher := ahocorasick.Compile(rule.Keywords, true)
	original := regexp.MustCompile(rule.Regex)
	for _, raw := range []string{"token = 'aZ8vQ2xR9mN6pL3t'", "Key\n='abcdef123456'", "api token isn't assigned", "key\xff=abcdef123456", "key" + strings.Repeat(" ", 23) + "=abcdef123456"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16384 {
			t.Skip()
		}
		if original.MatchString(raw) && !guardAccepts(guard, matcher, raw) {
			t.Fatal("guard omitted a regex match")
		}
	})
}
