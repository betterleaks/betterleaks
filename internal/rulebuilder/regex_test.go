package rulebuilder

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/regexp"
)

func TestSemiGenericRegex(t *testing.T) {
	tests := []struct {
		name              string
		identifiers       []string
		secretRegex       string
		isCaseInsensitive []bool
		validStrings      []string
		invalidStrings    []string
	}{
		{
			name:              "secret is case sensitive, if isCaseInsensitive is false",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{false},
			validStrings:      []string{"api_key=xxx"},
			invalidStrings:    []string{"api_key=XXX", "api_key=xXx"},
		},
		{
			name:              "secret is case insensitive, if isCaseInsensitive is true",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true},
			validStrings:      []string{"api_key=xxx", "api_key=XXX", "api_key=xXx"},
			invalidStrings:    []string{"api_key=x!x"},
		},
		{
			name:              "identifier is case insensitive, regardless of isCaseInsensitive",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings:      []string{"api_key=xxx", "ApI_KeY=xxx", "aPi_kEy=xxx", "API_KEY=xxx"},
			invalidStrings:    []string{"api!key=xxx"},
		},
		{
			name:              "identifier can be case sensitive",
			identifiers:       []string{"(?-i:[Aa]pi_?[Kk]ey|API_?KEY)"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings:      []string{"apikey=xxx", "ApiKey=xxx", "Apikey=xxx", "APIKEY=xxx", "api_key=xxx"},
			invalidStrings:    []string{"ApIKeY=xxx", "aPikEy=xxx"},
		},
		{
			name:              "identifier can be part of a longer word",
			identifiers:       []string{"key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings:      []string{"mykey=xxx", "keys=xxx", "key1=xxx", "keystore=xxx", "monkey=xxx"},
			invalidStrings:    []string{},
		},
		{
			name:              "identifier may be followed by specific characters",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings: []string{
				"api_key-----=xxx",
				"api_key.....=xxx",
				"api_key_____=xxx",
				"'''api_key'''=xxx",
				`"""api_key"""=xxx`,
				"api_key          =xxx",
				"api_key\t\t\t\t\t=xxx",
				"api_key\n\n\n=xxx", // potentially invalid?,
				"api_key\r\n=xxx",
				// "api_key|||=xxx",
			},
			invalidStrings: []string{
				"api_key&=xxx",
				"$api_key$=xxx",
				"%api_key%=xxx",
				"api_key[0]=xxx",
				"api_key/*REMOVE*/=xxx",
			},
		},
		{
			name:              "identifier and secret must be separated by specific operators",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings: []string{
				"api_key=xxx",
				"api_key: xxx",
				"<api_key>xxx",
				"api_key:=xxx",
				"api_key:::=xxx",
				// "api_key||:=xxx", // this isn't anything
				// "api_key <= xxx",
				"api_key => xxx",
				"api_key ?= xxx",
				"api_key, xxx",
			},
			invalidStrings: []string{
				"api_keyxxx",
				"api_key\txxx", // potentially valid in a tab-separated file
				"api_key; xxx",
				"api_key<xxx>",
				"api_key&xxx",
				"api_key = true ? 'xxx' : 'yyy'",
			},
		},
		{
			name:              "secret is limited by specific boundaries",
			identifiers:       []string{"api_key"},
			secretRegex:       `[a-z]{3}`,
			isCaseInsensitive: []bool{true, false},
			validStrings: []string{
				"api_key=    xxx ",
				"api_key=xxx\n",
				"api_key=xxx\r\n",
				"api_key=\n\n\n\n\nxxx", // potentially invalid (e.g. .env.example)
				"api_key=\r\n\r\nxxx",
				"api_key=\t\t\t\txxx\t",
				"api_key======xxx;",
				"api_key='''xxx'''",
				`api_key="""xxx"""`,
				"api_key=```xxx```",
				`api_key="xxx'`, // could try to match only same opening and closing quotes, might not be worth the complexity
				`api_key="don't do it!"`,
				`api_key="xxx;notpartofthematch"`,
			},
			invalidStrings: []string{
				"api_key=_xxx",
				"api_key=xxx_",
				"api_key=$xxx",
				"api_key=%xxx%",
				"api_key=[xxx]",
				"api_key=(xxx)",
				"api_key=<xxx>",
				"api_key={xxx}",
				"<api_key>xxx</api_key>",            // potentially valid
				"example.com?api_key=xxx&other=yyy", // potentially valid
			},
		},
		// Note: these test cases do not necessarily prescribe the expected behavior of the function,
		// but rather document the current behavior, to ensure that future changes are intentional.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, isCaseInsensitive := range tt.isCaseInsensitive {
				regex := regexp.MustCompile(semiGenericRegex(tt.identifiers, tt.secretRegex, isCaseInsensitive))
				for _, validString := range tt.validStrings {
					if !regex.MatchString(validString) {
						t.Errorf("Expected match, but got none, \nfor semiGenericRegex(%v, /%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
							tt.identifiers, tt.secretRegex, isCaseInsensitive, validString, regex)
					}
				}
				for _, invalidString := range tt.invalidStrings {
					if regex.MatchString(invalidString) {
						t.Errorf("Expected no match, but got one, \nfor semiGenericRegex(%v, /%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
							tt.identifiers, tt.secretRegex, isCaseInsensitive, invalidString, regex)
					}
				}
			}
		})
	}
}

func TestUniqueTokenRegex(t *testing.T) {
	tests := []struct {
		name              string
		secretRegex       string
		isCaseInsensitive bool
		validStrings      []string
		invalidStrings    []string
	}{
		{
			name:              "case sensitive secret",
			secretRegex:       `[a-c]{3}`,
			isCaseInsensitive: false,
			validStrings:      []string{"abc"},
			invalidStrings:    []string{"ABC", "Abc"},
		},
		{
			name:              "case insensitive secret",
			secretRegex:       `[a-c]{3}`,
			isCaseInsensitive: true,
			validStrings:      []string{"abc", "ABC", "Abc"},
			invalidStrings:    []string{"123"},
		},
		{
			name:              "allowed boundaries",
			secretRegex:       `[a-c]{3}`,
			isCaseInsensitive: false,
			validStrings: []string{
				"abc",
				" abc ",
				"\nabc\n",
				"\r\nabc\r\n",
				"\tabc\t",
				"'abc'",
				`"abc"`,
				"```abc```",
				"my abc's",
				".com?abc",
				"(abc)", // command wrappers, e.g. Bash(export KEY=abc)
				`Bash(curl -H \"X: abc\")`,
			},
			invalidStrings: []string{
				"abcabc",
				"_abc_",
				".com?abc&def", // potentially valid
				"/*abc*/",
				"<abc>",
				"<str>abc</str>", // potentially valid
				"{{{abc}}}",
				"abc, d",
			},
		},
		// Note: these test cases do not necessarily prescribe the expected behavior of the function,
		// but rather document the current behavior, to ensure that future changes are intentional.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex := regexp.MustCompile(uniqueTokenRegex(tt.secretRegex, tt.isCaseInsensitive))
			for _, validString := range tt.validStrings {
				if !regex.MatchString(validString) {
					t.Errorf("Expected match, but got none, \nfor uniqueTokenRegex(/%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
						tt.secretRegex, tt.isCaseInsensitive, validString, regex)
				}
			}
			for _, invalidString := range tt.invalidStrings {
				if regex.MatchString(invalidString) {
					t.Errorf("Expected no match, but got one, \nfor uniqueTokenRegex(/%v/, caseInsensitive=%v).MatchString(`%v`)\n%v",
						tt.secretRegex, tt.isCaseInsensitive, invalidString, regex)
				}
			}
		})
	}
}

func TestDomain(t *testing.T) {
	const (
		pat    = `[A-Za-z0-9]{4}`
		within = 86
	)
	tiles := `https://api.maptiler.com/tiles/v2/[z]/[x]/[y].webp?key=Ab12`
	cased := `https://API.MapTiler.com/maps/x?format=json&key=Ab12`
	port := `https://maptiler.com:443/a?key=Ab12`

	tests := []struct {
		name           string
		domains        []string
		params         []string
		pattern        string
		within         int
		validStrings   []string
		invalidStrings []string
		want           string
	}{
		{
			name:    "query parameter on the service domain",
			domains: []string{"maptiler.com"},
			params:  []string{"key"},
			pattern: pat,
			within:  within,
			want:    "Ab12",
			validStrings: []string{
				tiles,
				cased,
				port,
				tiles + "&other=1",
				cased + "&other=1",
				port + "&other=1",
				`https://maptiler.com/a?key=Ab12#section`,
				`"https://api.maptiler.com/v1?key=Ab12"`,
				`https://user:pass@api.maptiler.com/a?key=Ab12`,
				`HTTPS://API.MAPTILER.COM/v1?key=Ab12`,
			},
			invalidStrings: []string{
				`https://api.maptiler.com.example.io/v1?key=Ab12`,
				`https://notmaptiler.com/v1?key=Ab12`,
				`https://foo-maptiler.com/v1?key=Ab12`,
				`https://api.maptiler.com/v1?token=Ab12`,
				`https://api.maptiler.com/v1?mykey=Ab12`,
				`https://API.MapTiler.com/maps/x?format=json&KEY=Ab12`,
				`https://api.maptiler.com/v1?Key=Ab12`,
				`https://api.maptiler.com/v1?key=Ab123`,
				`https://maptilerXcom/v1?key=Ab12`,
				// The first "/" is outside the repeat, so one more "a" exceeds {0,within}.
				"https://api.maptiler.com/" + strings.Repeat("a", within+1) + "?key=Ab12",
			},
		},
		{
			name:         "secret stays case sensitive",
			domains:      []string{"maptiler.com"},
			params:       []string{"key"},
			pattern:      `[a-z]{4}`,
			within:       within,
			want:         "abcd",
			validStrings: []string{`https://API.MapTiler.com/v1?key=abcd`},
			invalidStrings: []string{
				`https://API.MapTiler.com/v1?key=ABCD`,
				`https://API.MapTiler.com/v1?KEY=abcd`,
				`https://api.maptiler.com/v1?key=Abcd`,
			},
		},
		{
			name:    "leading (?i) makes the secret case insensitive",
			domains: []string{"maptiler.com"},
			params:  []string{"key"},
			pattern: `(?i)[a-z]{4}`,
			within:  within,
			validStrings: []string{
				`https://maptiler.com/v1?key=abcd`,
				`https://maptiler.com/v1?key=ABCD`,
				`https://maptiler.com/v1?key=AbCd`,
			},
			invalidStrings: []string{
				`https://maptiler.com/v1?key=ab12`,
				`https://maptiler.com/v1?KEY=ABCD`,
			},
		},
		{
			name:    "host case fold includes percent hex; parameter names do not",
			domains: []string{"ex%4Ample.com"},
			params:  []string{"a%2eb"},
			pattern: pat,
			within:  within,
			want:    "Ab12",
			validStrings: []string{
				`https://ex%4Ample.com/v1?a%2eb=Ab12`,
				`https://EX%4ample.COM/v1?a%2eb=Ab12`,
				`https://ex%4aMPLE.com/v1?a%2eb=Ab12`,
			},
			invalidStrings: []string{
				`https://example.com/v1?a%2eb=Ab12`,
				`https://ex%4Bmple.com/v1?a%2eb=Ab12`,
				`https://ex%4Ample.com/v1?A%2eb=Ab12`,
				`https://ex%4Ample.com/v1?a%2Eb=Ab12`,
			},
		},
		{
			name:         "domain and parameter are literals",
			domains:      []string{"map.tiler.com"},
			params:       []string{"k.ey"},
			pattern:      pat,
			within:       within,
			want:         "Ab12",
			validStrings: []string{`https://api.map.tiler.com/v1?k.ey=Ab12`},
			invalidStrings: []string{
				`https://api.mapXtiler.com/v1?k.ey=Ab12`,
				`https://api.map.tiler.com/v1?kXey=Ab12`,
				`https://api.map.tiler.com.example.io/v1?k.ey=Ab12`,
			},
		},
		{
			name:    "any listed domain and parameter",
			domains: []string{"example.com", "example.com.evil.net"},
			params:  []string{"key", "token"},
			pattern: pat,
			within:  within,
			want:    "Ab12",
			validStrings: []string{
				`https://example.com/v1?key=Ab12`,
				`https://a.example.com/v1?token=Ab12`,
				`https://example.com.evil.net/v1?key=Ab12`,
				`https://api.example.com.evil.net/v1?token=Ab12&other=1`,
			},
			invalidStrings: []string{
				`https://example.com.notevil.net/v1?key=Ab12`,
				`https://notexample.com/v1?key=Ab12`,
				`https://example.org/v1?key=Ab12`,
				`https://example.com/v1?secret=Ab12`,
			},
		},
		{
			name:    "longer domain is not hidden by a shorter prefix",
			domains: []string{"example.com.evil.net", "example.com"},
			params:  []string{"key"},
			pattern: pat,
			within:  within,
			want:    "Ab12",
			validStrings: []string{
				`https://example.com/v1?key=Ab12`,
				`https://example.com.evil.net/v1?key=Ab12`,
			},
			invalidStrings: []string{
				`https://example.com.evil.net.other/v1?key=Ab12`,
			},
		},
		{
			name:    "secret regex is inserted as written",
			domains: []string{"maptiler.com"},
			params:  []string{"key"},
			pattern: `A.12`,
			within:  within,
			validStrings: []string{
				`https://maptiler.com/v1?key=Ab12`,
				`https://maptiler.com/v1?key=AX12`,
			},
			invalidStrings: []string{
				`https://maptiler.com/v1?key=ab12`,
				`https://maptiler.com/v1?key=A12`,
			},
		},
		{
			name:    "within zero allows the introducer next to the domain",
			domains: []string{"maptiler.com"},
			params:  []string{"key"},
			pattern: pat,
			within:  0,
			want:    "Ab12",
			validStrings: []string{
				`https://maptiler.com?key=Ab12`,
				`https://maptiler.com/?key=Ab12`,
				`https://API.MapTiler.com?key=Ab12&other=1`,
			},
			invalidStrings: []string{
				`https://maptiler.com/a?key=Ab12`,
				tiles,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := Domain(tt.domains, tt.params, tt.pattern, tt.within)
			for _, engine := range engines {
				t.Run(engine.Version(), func(t *testing.T) {
					re := compileForEngine(t, engine, pattern)
					if re.NumSubexp() != 1 {
						t.Fatalf("expected one capture group, got %d\n%s", re.NumSubexp(), re)
					}
					for _, validString := range tt.validStrings {
						got, ok := domainSecret(re, validString)
						if !ok {
							t.Errorf("Expected match, but got none, \nfor Domain(%v, %v, /%s/, %d).MatchString(`%s`)\n%s",
								tt.domains, tt.params, tt.pattern, tt.within, validString, re)
							continue
						}
						if tt.want != "" && got != tt.want {
							t.Errorf("capture %q, want %q\nfor Domain(%v, %v, /%s/, %d) on `%s`\n%s",
								got, tt.want, tt.domains, tt.params, tt.pattern, tt.within, validString, re)
						}
						if tt.want == "" && !strings.Contains(validString, "="+got) {
							t.Errorf("capture %q is not the query value of `%s`\n%s", got, validString, re)
						}
					}
					for _, invalidString := range tt.invalidStrings {
						if re.MatchString(invalidString) {
							t.Errorf("Expected no match, but got one, \nfor Domain(%v, %v, /%s/, %d).MatchString(`%s`)\n%s",
								tt.domains, tt.params, tt.pattern, tt.within, invalidString, re)
						}
					}
				})
			}
		})
	}
}

// TestDomainSecretSuffix checks the characters that end a query secret.
// The suffix is the shared secret terminator, plus "&", "#", "%", "\",
// the punctuation ".,/", and the brackets "<>]}".
// The secret pattern is unbounded alphanumerics, so the suffix is what ends
// the capture: "&" stops "&amp;", "\" stops "\u0026", and "%" stops "%26".
func TestDomainSecretSuffix(t *testing.T) {
	const (
		secret = "Ab12"
		within = 32
	)
	pattern := Domain([]string{"example.com"}, []string{"key"}, `[A-Za-z0-9]+`, within)
	at := func(tail string) string {
		return "https://example.com?key=" + secret + tail
	}
	tests := []struct {
		name  string
		in    string
		match bool
	}{
		{"end of text", at(""), true},
		{"ampersand", at("&other=1"), true},
		{"html amp", at("&amp;other=1"), true},
		{"fragment", at("#section"), true},
		{"backslash", at(`\rest`), true},
		{"json u0026", at(`\u0026other=1`), true},
		{"semicolon", at(";other=1"), true},
		{"closing paren", at(")rest"), true},
		{"double quote", at(`"rest`), true},
		{"single quote", at("'rest"), true},
		{"backtick", at("\x60rest"), true},
		{"escaped quote", at(`\"rest`), true},
		{"space", at(" rest"), true},
		{"newline", at("\nrest"), true},
		{"tab", at("\trest"), true},
		{"escaped n", at(`\nrest`), true},
		{"escaped r", at(`\rrest`), true},
		{"percent-encoded ampersand", at("%26other=1"), true},
		{"slash", at("/rest"), true},
		{"comma", at(",rest"), true},
		{"dot", at(".rest"), true},
		{"less than", at("<rest"), true},
		{"greater than", at(">rest"), true},
		{"closing square bracket", at("]rest"), true},
		{"closing curly brace", at("}rest"), true},
		{"plus", at("+rest"), false},
		{"underscore", at("_rest"), false},
		{"equals", at("=rest"), false},
		{"opening paren", at("(rest"), false},
		{"opening square bracket", at("[rest"), false},
		{"opening curly brace", at("{rest"), false},
	}

	for _, engine := range engines {
		t.Run(engine.Version(), func(t *testing.T) {
			re := compileForEngine(t, engine, pattern)
			for _, tc := range tests {
				got, ok := domainSecret(re, tc.in)
				if tc.match {
					if !ok || got != secret {
						t.Errorf("%s: capture %q, want %q\nfor %q\n%s", tc.name, got, secret, tc.in, re)
					}
					continue
				}
				if ok {
					t.Errorf("%s: expected no match, got %q\nfor %q\n%s", tc.name, got, tc.in, re)
				}
			}
		})
	}
}

// within is the {0,within} run after the first ":", "/", "?", or "\".
// The parameter name, and "&amp;" or "\u0026", sit outside that run.
func TestDomainWithin(t *testing.T) {
	const (
		pat   = `[A-Za-z0-9]{4}`
		value = "Ab12"
	)
	gaps := []struct {
		gap    string
		within int
	}{
		{"/tiles/v2/[z]/[x]/[y].webp?key=", len("/tiles/v2/[z]/[x]/[y].webp") - 1},
		{"/maps/x?format=json&key=", len("/maps/x?format=json") - 1},
		{":443/a?key=", len(":443/a") - 1},
		{"?key=", 0},
		{"/?key=", 0},
		{"?format=json&key=", len("?format=json") - 1},
		{"/a?key=", len("/a") - 1},
		{"?x=1&amp;key=", len("?x=1") - 1},
		{`?x=1\u0026key=`, len("?x=1") - 1},
	}
	for _, tc := range gaps {
		t.Run(tc.gap, func(t *testing.T) {
			in := "https://api.maptiler.com" + tc.gap + value
			exact := Domain([]string{"maptiler.com"}, []string{"key"}, pat, tc.within)
			for _, engine := range engines {
				re := compileForEngine(t, engine, exact)
				if got, ok := domainSecret(re, in); !ok || got != value {
					t.Errorf("%s: within %d should match %q, got %q\n%s", engine.Version(), tc.within, in, got, re)
				}
				if tc.within == 0 {
					continue
				}
				re = compileForEngine(t, engine, Domain([]string{"maptiler.com"}, []string{"key"}, pat, tc.within-1))
				if re.MatchString(in) {
					t.Errorf("%s: within %d should not match %q\n%s", engine.Version(), tc.within-1, in, re)
				}
			}
		})
	}

	gap := "/tiles/v2/[z]/[x]/[y].webp?key="
	stretched := "/tiles/v2/[z]/[x]/[y].webpx?key="
	pattern := Domain([]string{"maptiler.com"}, []string{"key"}, pat, len("/tiles/v2/[z]/[x]/[y].webp")-1)
	for _, engine := range engines {
		re := compileForEngine(t, engine, pattern)
		if got, ok := domainSecret(re, "https://api.maptiler.com"+gap+value); !ok || got != value {
			t.Errorf("%s: path at the within limit should match, got %q\n%s", engine.Version(), got, re)
		}
		if re.MatchString("https://api.maptiler.com" + stretched + value) {
			t.Errorf("%s: path stretched past within should not match\n%s", engine.Version(), re)
		}
	}

	// The parameter name is outside the budget, so "key" and "token" share it.
	// "/a?name=" needs one character ("a") after the "/".
	both := Domain([]string{"maptiler.com"}, []string{"key", "token"}, pat, len("/a")-1)
	for _, engine := range engines {
		re := compileForEngine(t, engine, both)
		for _, in := range []string{
			"https://maptiler.com?key=" + value,
			"https://maptiler.com?token=" + value,
			"https://maptiler.com/a?key=" + value,
			"https://maptiler.com/a?token=" + value,
		} {
			if got, ok := domainSecret(re, in); !ok || got != value {
				t.Errorf("%s: expected capture %s for %q, got %q\n%s", engine.Version(), value, in, got, re)
			}
		}
		for _, in := range []string{
			"https://maptiler.com/aa?key=" + value,
			"https://maptiler.com/aa?token=" + value,
		} {
			if re.MatchString(in) {
				t.Errorf("%s: expected no match for %q\n%s", engine.Version(), in, re)
			}
		}
	}
}

func TestDomainRejects(t *testing.T) {
	pat := `[A-Za-z0-9]{4}`
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: did not reject", name)
			}
		}()
		fn()
	}
	mustPanic("negative within", func() { Domain([]string{"maptiler.com"}, []string{"key"}, pat, -1) })
	mustPanic("within above 1000", func() { Domain([]string{"maptiler.com"}, []string{"key"}, pat, 1001) })
	mustPanic("empty pattern", func() { Domain([]string{"maptiler.com"}, []string{"key"}, "", 8) })
	mustPanic("no domains", func() { Domain(nil, []string{"key"}, pat, 8) })
	mustPanic("empty domain", func() { Domain([]string{""}, []string{"key"}, pat, 8) })
	mustPanic("no params", func() { Domain([]string{"maptiler.com"}, nil, pat, 8) })
	mustPanic("empty param", func() { Domain([]string{"maptiler.com"}, []string{"key", ""}, pat, 8) })

	if got := Domain([]string{"maptiler.com"}, []string{"key"}, pat, 0); !strings.Contains(got, `maptiler\.com`) {
		t.Fatalf("within 0 should build a pattern, got %s", got)
	}
	if got := Domain([]string{"maptiler.com"}, []string{"key"}, pat, 1000); !strings.Contains(got, `{0,1000}`) {
		t.Fatalf("within 1000 should allow 1000 characters after the first, got %s", got)
	}
}

func compileForEngine(t *testing.T, engine regexp.Engine, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.CompileWithEngine(pattern, engine)
	if err != nil {
		t.Fatalf("%s parse: %v\n%s", engine.Version(), err, pattern)
	}
	if err := re.Compile(); err != nil {
		t.Fatalf("%s compile: %v\n%s", engine.Version(), err, pattern)
	}
	return re
}

func domainSecret(re *regexp.Regexp, in string) (string, bool) {
	got := re.FindStringSubmatch(in)
	if len(got) != 2 {
		return "", false
	}
	return got[1], true
}
