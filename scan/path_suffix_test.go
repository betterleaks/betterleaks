package scan

import (
	"regexp"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
)

func TestPathSuffixParity(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range cfg.Rules {
		if rule.Path == "" {
			continue
		}
		suffixes := compilePathSuffixes(rule.Path)
		if rule.ID == "pkcs12-file" && len(suffixes) == 0 {
			t.Fatal("expected suffix proof")
		}
		original := regexp.MustCompile(rule.Path)
		for _, base := range []string{"key.p12", "key.pfx", "key.txt", ".p12", "x.P12", "\xff.pfx", "Key.pfx", "key\n.pfx"} {
			for _, prefix := range []string{"", "nested/", "nested\\", "./"} {
				path := prefix + base
				if original.MatchString(path) && !pathSuffixPossible(path, suffixes) {
					t.Fatalf("%s rejected %q", rule.ID, path)
				}
			}
		}
	}
	for _, pattern := range []string{`.*`, `(?m)foo$`, `(?:foo|bar)`} {
		if len(compilePathSuffixes(pattern)) != 0 {
			t.Fatalf("unexpected proof for %q", pattern)
		}
	}
	if pathSuffixPossible("file.txt", compilePathSuffixes(`(?i)\.(?:p12|pfx)$`)) {
		t.Fatal("noncandidate accepted")
	}
	for _, path := range []string{"K", "ſ", "long/path/K"} {
		if !pathSuffixPossible(path, compilePathSuffixes(`(?i)(?:k|s)$`)) {
			t.Fatal("Unicode fold rejected")
		}
	}
}

func FuzzPathSuffix(f *testing.F) {
	for _, pattern := range []string{`(?i)(?:^|/)[^/]+\.p(?:12|fx)$`, `(?i)key$`, `foo(?:bar)?$`, `foo[a-z]{0,2}bar$`} {
		f.Add(pattern, "test/key.P12")
	}
	f.Fuzz(func(t *testing.T, pattern, path string) {
		if len(pattern) > 256 || len(path) > 8192 {
			return
		}
		r, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		if r.MatchString(path) && !pathSuffixPossible(path, compilePathSuffixes(pattern)) {
			t.Fatalf("%q rejected %q", pattern, path)
		}
	})
}
