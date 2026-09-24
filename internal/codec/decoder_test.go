package codec

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand/v2"
	"net/url"
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

	fullDecode := func(data string) string {
		segments := []*EncodedSegment{}
		for {
			data, segments = Decode(data, segments)
			if len(segments) == 0 {
				return data
			}
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, encoding := range []struct {
				name   string
				encode func(string) string
			}{
				{"plain", func(s string) string { return s }},
				{"percent", url.PathEscape},
				{"hex", func(s string) string { return hex.EncodeToString([]byte(s)) }},
			} {
				t.Run(encoding.name, func(t *testing.T) {
					assert.Equal(t, tc.expected, fullDecode(encoding.encode(tc.chunk)))
				})
			}
		})
	}
}

func TestEncodingMatchBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        []encodingMatch
	}{
		{name: "empty", input: "", want: nil},
		{name: "no candidates", input: "plain text", want: nil},
		{
			name: "adjacent percent suppresses base64", input: "YWJjZGVmZ2hpamts%41",
			want: []encodingMatch{{encoding: encodings[0], startEnd: startEnd{16, 19}}},
		},
		{
			name: "preceding percent suppresses base64", input: "%41YWJjZGVmZ2hpamts",
			want: []encodingMatch{{encoding: encodings[0], startEnd: startEnd{0, 3}}},
		},
		{
			name: "separated encodings survive", input: "%41!YWJjZGVmZ2hpamts",
			want: []encodingMatch{
				{encoding: encodings[0], startEnd: startEnd{0, 3}},
				{encoding: encodings[3], startEnd: startEnd{4, 20}},
			},
		},
		{
			name: "adjacent equal kinds survive", input: "YWJjZGVmZ2hpamts=cXJzdHV2d3h5ekFC=",
			want: []encodingMatch{
				{encoding: encodings[3], startEnd: startEnd{0, 17}},
				{encoding: encodings[3], startEnd: startEnd{17, 34}},
			},
		},
		{
			name: "later matches survive compaction", input: "%41YWJjZGVmZ2hpamts=cXJzdHV2d3h5ekFC=!U+0041",
			want: []encodingMatch{
				{encoding: encodings[0], startEnd: startEnd{0, 3}},
				{encoding: encodings[3], startEnd: startEnd{20, 37}},
				{encoding: encodings[1], startEnd: startEnd{38, 44}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := findEncodingMatches(tc.input)
			if !assert.Len(t, got, len(tc.want)) {
				return
			}
			for i, want := range tc.want {
				assert.Equal(t, want.startEnd, got[i].startEnd)
				assert.Equal(t, want.encoding.kind, got[i].encoding.kind)
			}
		})
	}
}

func TestBase64PrefixAcceptsPrintableInput(t *testing.T) {
	for b := range byte(127) {
		if !printableASCII[b] {
			continue
		}
		for position := range 12 {
			data := []byte("printable123")
			data[position] = b
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
				value := encoding.EncodeToString(data)
				if !possibleBase64Prefix(value) {
					t.Fatalf("rejected accepted byte %d at position %d", b, position)
				}
			}
		}
	}
}

func FuzzBase64Prefix(f *testing.F) {
	for _, value := range []string{"abcdefghijklmnop", "YWJjZGVmZ2hpamts", "YWJj\r\nZGVmZ2hpamts", "YWJjZGVmZ2hpamts=", "cXJzdHV2d3h5ekFC", "_______-", "____++__", ""} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if !possibleBase64Prefix(value) && decodeBase64(value) != "" {
			t.Fatal("prefix rejected decodable printable input")
		}
	})
}

func TestBase64PrefixKeepsEncodingPrecedence(t *testing.T) {
	// A failed higher-precedence candidate still suppresses adjacent Base64.
	for _, value := range []string{"%00YWJjZGVmZ2hpamts", "YWJjZGVmZ2hpamts%00"} {
		decoded, segments := Decode(value, nil)
		if decoded != value || len(segments) != 0 {
			t.Fatal("changed failed-candidate precedence")
		}
	}
}

func TestBase64ScratchParity(t *testing.T) {
	// Compare against the previous allocating implementation, including the
	// transition from stack to heap storage and partially decoded failures.
	reference := func(value string) string {
		if !hasByte(value, likelyBase64Chars) {
			return ""
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
			decoded, err := encoding.DecodeString(value)
			if err == nil && isPrintableASCII(decoded) {
				return string(decoded)
			}
		}
		return ""
	}
	random := rand.New(rand.NewPCG(1, 2))
	for _, length := range []int{0, 1, 2, 3, 16, 255, 256, 257, 1024} {
		for range 100 {
			data := make([]byte, length)
			for i := range data {
				data[i] = byte(32 + random.IntN(95))
			}
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
				value := encoding.EncodeToString(data)
				for _, input := range []string{value, value + "-", value + "=", string(data)} {
					if got, want := decodeBase64(input), reference(input); got != want {
						t.Fatalf("length %d: got %q, want %q", length, got, want)
					}
				}
			}
		}
	}
}
