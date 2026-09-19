package regexspan

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/lucasjones/reggen"
)

func TestDefaultRuleWindows(t *testing.T) {
	cfg, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	planned := 0
	for _, rule := range cfg.Rules {
		if Compile(rule.Regex, rule.Keywords) == nil {
			continue
		}
		planned++
		t.Run(rule.ID, func(t *testing.T) {
			generator, err := reggen.NewGenerator(rule.Regex)
			if err != nil {
				t.Fatal(err)
			}
			generator.SetSeed(1)
			for range 10 {
				value := generator.Generate(8)
				text := strings.Repeat("unrelated filler\n", 100) + value + "\n" + strings.Repeat("other filler\n", 100) + value + "\n"
				checkWindows(t, rule.Regex, text, rule.Keywords)
			}
		})
	}
	t.Logf("derived windows for %d/%d default rules", planned, len(cfg.Rules))
}

func checkWindows(t testing.TB, pattern, text string, keywords []string) {
	t.Helper()
	plan := Compile(pattern, keywords)
	if plan == nil {
		return
	}
	re := regexp.MustCompile(pattern)
	matcher := ahocorasick.Compile(keywords, true)
	var windows Windows
	matcher.Visit(text, func(_ int, start, end int) bool {
		windows.Add(text, start, end, plan)
		return true
	})
	var got [][]int
	for _, span := range windows.Spans {
		if plan.RequiredByte != 0 && strings.IndexByte(text[span.Start:span.End], plan.RequiredByte) < 0 {
			continue
		}
		for _, match := range re.FindAllStringSubmatchIndex(text[span.Start:span.End], -1) {
			for i, offset := range match {
				if offset >= 0 {
					match[i] += span.Start
				}
			}
			got = append(got, match)
		}
	}
	want := re.FindAllStringSubmatchIndex(text, -1)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("pattern %q keywords %q text %q plan %+v windows %+v: got %v, want %v", pattern, keywords, text, plan, windows.Spans, got, want)
	}
}

func TestWindows(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		keys    []string
		text    string
	}{
		{`(?i)(?:access|auth|api|key|secret|token)\s{0,5}=\s{0,5}[a-z0-9+/]{10,}={0,3}(?:[\s;]|$)`, []string{"access", "auth", "api", "key", "secret", "token"}, "access = ABCDEFG1234;\nkey\n\n=\n\nA2345678901234567890\n"},
		{`\Akey:[a-z]+\z`, []string{"key"}, "key:abcd"},
		{`\Akey:[a-z]+\z`, []string{"key"}, strings.Repeat("x", 400) + "key:abcd"},
		{`(?m)^key:[a-z]+$`, []string{"key"}, "\nkey:abcd\nkey:efgh\n"},
		{`\bkey:[a-z]{3,6}\b`, []string{"key"}, " key:abcd " + strings.Repeat("x", 400) + "key:abcd "},
		{`(?i)key:[a-z]+`, []string{"key"}, "Key:ſecret\n\xffkey:value"},
		{`(?:^|[^a-zA-Z0-9])key[^\n]+`, []string{"key"}, "\U0001f600key:こんにちは\n key:end"},
		{`.{0,6}key(?:\n?[^\n]*){0,3}$`, []string{"key"}, "xxkey:abcd\nkey:efgh\nend\n" + strings.Repeat("z", 100)},
		{`(?i)(?:[_.-]pw|password)=[a-z]+`, []string{"_pw", "-pw", ".pw", "password"}, "_pw=abcd\n.password=efgh"},
		{`[a-z]{0,20}token[a-z]{0,20}`, []string{"token", "longtoken"}, strings.Repeat("longtoken", 500)},
		{`(?i)key\s{0,3}=[a-z]+`, []string{"key"}, strings.Repeat("key=value ", 3000)},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			if Compile(tc.pattern, tc.keys) == nil {
				t.Fatal("expected a plan")
			}
			checkWindows(t, tc.pattern, tc.text, tc.keys)
		})
	}
}

func TestCompileFallsBack(t *testing.T) {
	for _, pattern := range []string{`foo|bar`, `.*foo`, `(?s)foo.*`, `foo?`, `(?:foo)*`, `foo[\s\S]*`} {
		if plan := Compile(pattern, []string{"foo"}); plan != nil {
			t.Errorf("%q: unsafe plan %+v", pattern, plan)
		}
	}
}

func TestWindowsBoundScratch(t *testing.T) {
	text := strings.Repeat("key:value"+strings.Repeat(".", 100), 1000)
	plan := Compile(`key:(\w{1,8})`, []string{"key"})
	var windows Windows
	matcher := ahocorasick.Compile([]string{"key"}, true)
	matcher.Visit(text, func(_ int, start, end int) bool {
		windows.Add(text, start, end, plan)
		return true
	})
	if len(windows.Spans) != 1 || windows.Spans[0] != (Span{0, len(text)}) {
		t.Fatal("expected full-text fallback for excessive disjoint windows")
	}
	checkWindows(t, `key:(\w{1,8})`, text, []string{"key"})
}

func FuzzWindows(f *testing.F) {
	for _, seed := range []struct{ pattern, text, keywords string }{
		{`(?i)(?:access|auth|key|token)\s{0,3}=[a-z]{1,250}`, "key=abc\naccess=def", "access,auth,key,token"},
		{`(?i)key[^\n]+$`, "Key=ſecret\nkey=abc", "key"},
		{`.{0,10}foo(?:[^\n]*\n){0,3}[^\n]*$`, "foo\nabc\nfoo:end", "foo"},
		{`\bfoo[a-z]*\b`, "fooabc fooa\xfffoo", "foo"},
		{`(?i)\b(?P<scheme>https?)://([^@\s]{1,8})@([^/\s]+)`, "http://u:p@host\nhttps://plain/path", "http://,https://"},
	} {
		f.Add(seed.pattern, seed.text, seed.keywords)
	}
	f.Fuzz(func(t *testing.T, pattern, text, keywords string) {
		if len(pattern) > 256 || len(text) > 16000 || len(keywords) > 128 {
			return
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return
		}
		checkWindows(t, pattern, text, strings.Split(keywords, ","))
	})
}

func TestKeywordsAcrossCaptures(t *testing.T) {
	pattern := `(?i)\b(?P<uri>(?P<scheme>https?|postgres(?:ql)?)://(?P<user>[^:/@\s]{0,128}):(?P<password>[^/@\s]{1,256})@(?P<host>[^/\s]+))`
	keys := []string{"http://", "https://", "postgres://", "postgresql://"}
	if Compile(pattern, keys) == nil {
		t.Fatal("expected a plan across scheme capture and separator")
	}
	for _, value := range []string{"https://user:secret@host/path", "postgresql://:secret@host", "HTTP://user:secret@host", "http://user:secret@host https://user:other@host"} {
		text := strings.Repeat("ordinary text\n", 100) + value + "\n" + strings.Repeat("other text\n", 100) + value
		checkWindows(t, pattern, text, keys)
	}
}

func TestRequiredPunctuationProof(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    byte
	}{
		{`key=[a-z]+@host`, '='}, {`key(?:=[a-z]+|:[a-z]+)`, 0}, {`key(?:@[a-z]+)?`, 0}, {`key[.@][a-z]+`, 0}, {`key(?:@[a-z]+|@.*)`, '@'},
	} {
		plan := Compile(tc.pattern, []string{"key"})
		if plan == nil {
			t.Fatal(tc.pattern)
		}
		if plan.RequiredByte != tc.want {
			t.Fatalf("%s: got %q want %q", tc.pattern, plan.RequiredByte, tc.want)
		}
	}
}
