package codec

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		chunk    string
		expected string
		name     string
	}{
		{
			name:     "only b64 chunk",
			chunk:    `bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `longer-encoded-secret-test`,
		},
		{
			name:     "mixed content",
			chunk:    `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `token: longer-encoded-secret-test`,
		},
		{
			name:     "no chunk",
			chunk:    ``,
			expected: ``,
		},
		{
			name:     "env var (looks like all b64 decodable but has `=` in the middle)",
			chunk:    `some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=`,
			expected: `some-encoded-secret=test-secret-value`,
		},
		{
			name:     "has longer b64 inside",
			chunk:    `some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q="`,
			expected: `some-encoded-secret="longer-encoded-secret-test"`,
		},
		{
			name: "many possible i := 0substrings",
			chunk: `Many substrings in this slack message could be base64 decoded
				but only dGhpcyBlbmNhcHN1bGF0ZWQgc2VjcmV0 should be decoded.`,
			expected: `Many substrings in this slack message could be base64 decoded
				but only this encapsulated secret should be decoded.`,
		},
		{
			name:     "b64-url-safe: only b64 chunk",
			chunk:    `bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`,
			expected: `longer-encoded-secret-test`,
		},
		{
			name:     "b64-url-safe: mixed content",
			chunk:    `token: bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q`,
			expected: `token: longer-encoded-secret-test`,
		},
		{
			name:     "b64-url-safe: env var (looks like all b64 decodable but has `=` in the middle)",
			chunk:    `some-encoded-secret=dGVzdC1zZWNyZXQtdmFsdWU=`,
			expected: `some-encoded-secret=test-secret-value`,
		},
		{
			name:     "b64-url-safe: has longer b64 inside",
			chunk:    `some-encoded-secret="bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q"`,
			expected: `some-encoded-secret="longer-encoded-secret-test"`,
		},
		{
			name:     "b64-url-safe: hyphen url b64",
			chunk:    `Z2l0bGVha3M-PmZpbmRzLXNlY3JldHM`,
			expected: `gitleaks>>finds-secrets`,
		},
		{
			name:     "b64-url-safe: underscore url b64",
			chunk:    `YjY0dXJsc2FmZS10ZXN0LXNlY3JldC11bmRlcnNjb3Jlcz8_`,
			expected: `b64urlsafe-test-secret-underscores??`,
		},
		{
			name:     "invalid base64 string",
			chunk:    `a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`,
			expected: `a3d3fa7c2bb99e469ba55e5834ce79ee4853a8a3`,
		},
		{
			name:     "url encoded value",
			chunk:    `secret%3D%22q%24%21%40%23%24%25%5E%26%2A%28%20asdf%22`,
			expected: `secret="q$!@#$%^&*( asdf"`,
		},
		{
			name:     "hex encoded value",
			chunk:    `secret="466973684D617048756E6B79212121363334"`,
			expected: `secret="FishMapHunky!!!634"`,
		},
		{
			name:     "unicode encoded value",
			chunk:    `secret=U+0061 U+0062 U+0063 U+0064 U+0065 U+0066`,
			expected: "secret=abcdef",
		},
		{
			name:     "unicode encoded value backslashed",
			chunk:    `secret=\\u0068\\u0065\\u006c\\u006c\\u006f\\u0020\\u0077\\u006f\\u0072\\u006c\\u0064\\u0020\\u0064\\u0075\\u0064\\u0065`,
			expected: "secret=hello world dude",
		},
		{
			name:     "unicode encoded value backslashed mixed w/ hex",
			chunk:    `secret=\u0068\u0065\u006c\u006c\u006f\u0020\u0077\u006f\u0072\u006c\u0064 6C6F76656C792070656F706C65206F66206561727468`,
			expected: "secret=hello world lovely people of earth",
		},
	}

	decoder := NewDecoder()
	fullDecode := func(data string) string {
		segments := []*EncodedSegment{}
		for {
			data, segments = decoder.Decode(data, segments)
			if len(segments) == 0 {
				return data
			}
		}
	}

	// Test value decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fullDecode(tt.chunk))
		})
	}

	// Percent encode the values to test percent decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedChunk := url.PathEscape(tt.chunk)
			assert.Equal(t, tt.expected, fullDecode(encodedChunk))
		})
	}

	// Hex encode the values to test hex decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedChunk := hex.EncodeToString([]byte(tt.chunk))
			assert.Equal(t, tt.expected, fullDecode(encodedChunk))
		})
	}
}

func TestFindEncodingMatches(t *testing.T) {
	t.Run("no matches", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{"empty string", ""},
			{"plain text", "hello world"},
			{"short b64 run (15 chars)", "aBcDeFgHiJkLmNo"},
			{"percent with non-hex digits", "%GGhello"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Nil(t, findEncodingMatches(tt.input))
			})
		}
	})

	t.Run("base64 matches", func(t *testing.T) {
		tests := []struct {
			name     string
			input    string
			wantStr  string // expected matched substring
			wantKind encodingKind
		}{
			{
				name:     "16+ char b64 run",
				input:    "aBcDeFgHiJkLmNoPq",
				wantStr:  "aBcDeFgHiJkLmNoPq",
				wantKind: base64Kind,
			},
			{
				name:     "b64 with 1 trailing equals",
				input:    "aBcDeFgHiJkLmNoP=",
				wantStr:  "aBcDeFgHiJkLmNoP=",
				wantKind: base64Kind,
			},
			{
				name:     "b64 with 2 trailing equals",
				input:    "aBcDeFgHiJkLmNoP==",
				wantStr:  "aBcDeFgHiJkLmNoP==",
				wantKind: base64Kind,
			},
			{
				name:     "b64 stops at 2 trailing equals",
				input:    "aBcDeFgHiJkLmNoP===",
				wantStr:  "aBcDeFgHiJkLmNoP==",
				wantKind: base64Kind,
			},
			{
				name:     "31 hex chars falls to b64",
				input:    "aabbccdd00112233aabbccdd0011223",
				wantStr:  "aabbccdd00112233aabbccdd0011223",
				wantKind: base64Kind,
			},
			{
				name:     "mixed hex and non-hex is b64",
				input:    "aabbccddG0112233aabbccdd0011223",
				wantStr:  "aabbccddG0112233aabbccdd0011223",
				wantKind: base64Kind,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches := findEncodingMatches(tt.input)
				assert.Len(t, matches, 1)
				assert.Equal(t, tt.wantKind, matches[0].encoding.kind)
				assert.Equal(t, tt.wantStr, tt.input[matches[0].start:matches[0].end])
			})
		}
	})

	t.Run("hex matches", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{"exactly 32 hex chars", "aabbccdd00112233aabbccdd00112233"},
			{"64 hex chars", "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches := findEncodingMatches(tt.input)
				assert.Len(t, matches, 1)
				assert.Equal(t, hexKind, matches[0].encoding.kind)
			})
		}
	})

	t.Run("percent matches", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			wantStr string
		}{
			{
				name:    "single %XX",
				input:   "hello%20world",
				wantStr: "%20",
			},
			{
				name:    "greedy span to last %XX on line",
				input:   "%20stuff%3D",
				wantStr: "%20stuff%3D",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches := findEncodingMatches(tt.input)
				assert.Len(t, matches, 1)
				assert.Equal(t, percentKind, matches[0].encoding.kind)
				assert.Equal(t, tt.wantStr, tt.input[matches[0].start:matches[0].end])
			})
		}
	})

	t.Run("percent does not cross newlines", func(t *testing.T) {
		input := "%20hello\n%3D"
		matches := findEncodingMatches(input)
		assert.Len(t, matches, 2)
		assert.Equal(t, "%20", input[matches[0].start:matches[0].end])
		assert.Equal(t, "%3D", input[matches[1].start:matches[1].end])
	})

	t.Run("unicode matches", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			wantStr string
		}{
			{
				name:    "U+XXXX at end of string",
				input:   "U+0041",
				wantStr: "U+0041",
			},
			{
				name:    "U+XXXX with trailing whitespace",
				input:   "U+0041 ",
				wantStr: "U+0041",
			},
			{
				name:    "multiple U+XXXX sequences",
				input:   "U+0048 U+0069",
				wantStr: "U+0048 U+0069",
			},
			{
				name:    "single backslash escape sequence",
				input:   `\u0048\u0069\u0021\u0021\u0021\u0021`,
				wantStr: `\u0048\u0069\u0021\u0021\u0021\u0021`,
			},
			{
				name:    "double backslash escape sequence",
				input:   `\\u0048\\u0069`,
				wantStr: `\\u0048\\u0069`,
			},
			{
				name:    "case insensitive uppercase U",
				input:   `\U0048\U0069\U0021\U0021\U0021\U0021`,
				wantStr: `\U0048\U0069\U0021\U0021\U0021\U0021`,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches := findEncodingMatches(tt.input)
				assert.Len(t, matches, 1)
				assert.Equal(t, unicodeKind, matches[0].encoding.kind)
				assert.Equal(t, tt.wantStr, tt.input[matches[0].start:matches[0].end])
			})
		}
	})

	t.Run("not unicode", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{"U+XXXX without trailing whitespace or end", "U+0041X"},
			{"backslash not followed by u", `\n\t\r`},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for _, m := range findEncodingMatches(tt.input) {
					assert.NotEqual(t, unicodeKind, m.encoding.kind)
				}
			})
		}
	})

	t.Run("precedence and multi-type", func(t *testing.T) {
		tests := []struct {
			name      string
			input     string
			wantKinds []encodingKind
		}{
			{
				name:      "percent wins over overlapping b64",
				input:     "secret%3D%22longvalue1234567%22",
				wantKinds: []encodingKind{percentKind},
			},
			{
				name:      "percent and b64 in same string",
				input:     `%20%20 bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
				wantKinds: []encodingKind{percentKind, base64Kind},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches := findEncodingMatches(tt.input)
				assert.Len(t, matches, len(tt.wantKinds))
				for i, wk := range tt.wantKinds {
					assert.Equal(t, wk, matches[i].encoding.kind)
				}
			})
		}
	})
}

func TestDecodeUnicode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"single U+XXXX", "U+0041", "A"},
		{"U+XXXX with surrounding text", "key=U+0041", "key=A"},
		{"mixed single and double backslash", `\u0041\\u0042`, "AB"},
		{"uppercase U in escape", `\U0041\U0042`, "AB"},
		{"no unicode returns unchanged", "just plain text", "just plain text"},
		{"invalid hex in U+XXXX returns unchanged", "U+ZZZZ", "U+ZZZZ"},
		{"invalid hex in backslash escape returns unchanged", `\uZZZZ`, `\uZZZZ`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, decodeUnicode(tt.input))
		})
	}
}

func TestDecodeEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		chunk    string
		expected string
	}{
		{
			name:     "long identifier not falsely decoded",
			chunk:    "SomeVeryLongVariable",
			expected: "SomeVeryLongVariable",
		},
		{
			name:     "hex exactly 32 chars decodes",
			chunk:    hex.EncodeToString([]byte("abcdefghijklmnop")),
			expected: "abcdefghijklmnop",
		},
		{
			name:     "double encoded percent",
			chunk:    url.PathEscape(url.PathEscape("hello=world")),
			expected: "hello=world",
		},
		{
			name:     "percent then b64 in same string",
			chunk:    `%48%65%6C%6C%6F token=bG9uZ2VyLWVuY29kZWQtc2VjcmV0LXRlc3Q=`,
			expected: `Hello token=longer-encoded-secret-test`,
		},
		{
			name:     "many short words no false positives",
			chunk:    "func main() { fmt.Println(x, y, z) }",
			expected: "func main() { fmt.Println(x, y, z) }",
		},
		{
			name:     "newline separates independent hex matches",
			chunk:    hex.EncodeToString([]byte("line-one-secret!")) + "\n" + hex.EncodeToString([]byte("line-two-secret!")),
			expected: "line-one-secret!\nline-two-secret!",
		},
		{
			name:     "U+XXXX sequence fully decodes",
			chunk:    "U+0073 U+0065 U+0063 U+0072 U+0065 U+0074",
			expected: "secret",
		},
		{
			name:     "long hex-only string non-printable ascii unchanged",
			chunk:    strings.Repeat("ff", 16),
			expected: strings.Repeat("ff", 16),
		},
	}

	decoder := NewDecoder()
	fullDecode := func(data string) string {
		segments := []*EncodedSegment{}
		for {
			data, segments = decoder.Decode(data, segments)
			if len(segments) == 0 {
				return data
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fullDecode(tt.chunk))
		})
	}
}
