package codec

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand/v2"
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
			// Same value as "hyphen url b64" above, padded.
			// Python's base64.urlsafe_b64encode always pads.
			name:     "b64-url-safe: padded hyphen url b64",
			chunk:    `YmV0dGVybGVha3M-PmZpbmRzLXNlY3JldHM=`,
			expected: `betterleaks>>finds-secrets`,
		},
		{
			// Same value, standard alphabet without padding, as produced by
			// Java's Base64.getEncoder().withoutPadding().
			name:     "unpadded standard b64",
			chunk:    `YmV0dGVybGVha3M+PmZpbmRzLXNlY3JldHM`,
			expected: `betterleaks>>finds-secrets`,
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
	// Also exercise each alignment after short alphabet runs and binary bytes.
	prefixes := []string{""}
	for offset := range 32 {
		prefixes = append(prefixes, strings.Repeat("abc!def\xff", 4)+strings.Repeat("!", offset))
	}
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
		{name: "code point within a short alphabet run", input: "abcU+0041 ", want: nil},
		{name: "15 alphabet bytes", input: "YWJjZGVmZ2hpamt", want: nil},
		{name: "16 alphabet bytes at EOF", input: "YWJjZGVmZ2hpamts", want: []encodingMatch{{encodings[3], startEnd{0, 16}}}},
		{name: "32 hex bytes at EOF", input: strings.Repeat("41", 16), want: []encodingMatch{{encodings[2], startEnd{0, 32}}}},
		{name: "escaped unicode", input: `\u0041\u0042 `, want: []encodingMatch{{encodings[1], startEnd{0, 12}}}},

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
			for _, prefix := range prefixes {
				got := findEncodingMatches(prefix + tc.input)
				if !assert.Len(t, got, len(tc.want), "offset %d", len(prefix)) {
					continue
				}
				for i, want := range tc.want {
					assert.Equal(t, startEnd{len(prefix) + want.start, len(prefix) + want.end}, got[i].startEnd)
					assert.Equal(t, want.encoding.kind, got[i].encoding.kind)
				}
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
		for _, encoding := range base64Encodings {
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

func FuzzDecodeBase64Payload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\t\n\v\f\r\x1b~"))
	f.Add([]byte("\xff\xfe\x00"))
	f.Add([]byte("雪\u0301"))
	f.Add([]byte(strings.Repeat("printable!", 31) + "\x7f"))
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	f.Add(allBytes)

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 16<<10 {
			t.Skip()
		}
		// The suffix clears the minimum length and includes '+' (or '-') in
		// every alignment, so the decoder's identifier heuristic admits it.
		value := string(body) + "~~~~~~~~~~~~"
		accept := true
		for _, b := range body {
			if b < 0x09 || b > 0x7e {
				accept = false
				break
			}
		}
		const prefix = "雪\x00\x1b\x7f!"
		const neighbor = "fixture 1234~~~~"
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			token := enc.EncodeToString([]byte(value))
			next := enc.EncodeToString([]byte(neighbor))
			raw := prefix + token + "!" + next
			want, count := token, 1
			if accept {
				want, count = value, 2
			}
			decoded, segments := Decode(raw, nil)
			if decoded != prefix+want+"!"+neighbor || len(segments) != count {
				t.Fatalf("padding/alphabet %q, body %x: incorrect decoded text or segment count", enc.EncodeToString([]byte("~~~!")), body)
			}
			if accept {
				assert.Equal(t, []int{len(prefix), len(prefix) + len(token)}, AdjustMatchIndex(segments, []int{len(prefix), len(prefix) + len(value)}))
			}
			// Even a rejected binary token must leave the neighboring token's
			// source coordinates intact.
			start := len(prefix) + len(want) + 1
			assert.Equal(t, []int{len(prefix) + len(token) + 1, len(raw)}, AdjustMatchIndex(segments, []int{start, start + len(neighbor)}))
		}
	})
}
