package codec

import (
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	fullDecodeBytes := func(data string) string {
		decoder := NewDecoder()
		defer decoder.Release()
		current := []byte(data)
		segments := []*EncodedSegment{}
		for {
			current, segments = decoder.DecodeBytes(current, segments)
			if len(segments) == 0 {
				return string(current)
			}
		}
	}

	// Test value decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, fullDecode(tt.chunk))
			assert.Equal(t, tt.expected, fullDecodeBytes(tt.chunk))
		})
	}

	// Percent encode the values to test percent decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedChunk := url.PathEscape(tt.chunk)
			assert.Equal(t, tt.expected, fullDecode(encodedChunk))
			assert.Equal(t, tt.expected, fullDecodeBytes(encodedChunk))
		})
	}

	// Hex encode the values to test hex decoding
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encodedChunk := hex.EncodeToString([]byte(tt.chunk))
			assert.Equal(t, tt.expected, fullDecode(encodedChunk))
			assert.Equal(t, tt.expected, fullDecodeBytes(encodedChunk))
		})
	}
}

func TestEncodingMatchFilterPreservesNeighborPrecedence(t *testing.T) {
	match := func(encodingIndex, start, end int) encodingMatch {
		return encodingMatch{
			encoding: encodings[encodingIndex],
			startEnd: startEnd{start: start, end: end},
		}
	}

	tests := []struct {
		name    string
		matches []encodingMatch
		want    []encodingKind
	}{
		{
			name:    "higher-precedence previous suppresses touching next",
			matches: []encodingMatch{match(0, 0, 3), match(3, 3, 6)},
			want:    []encodingKind{percentKind},
		},
		{
			name:    "higher-precedence next suppresses touching previous",
			matches: []encodingMatch{match(3, 0, 3), match(0, 3, 6)},
			want:    []encodingKind{percentKind},
		},
		{
			name:    "equal precedence retains both",
			matches: []encodingMatch{match(3, 0, 3), match(3, 3, 6)},
			want:    []encodingKind{base64Kind, base64Kind},
		},
		{
			name:    "non-overlapping neighbors retain both",
			matches: []encodingMatch{match(0, 0, 2), match(3, 3, 6)},
			want:    []encodingKind{percentKind, base64Kind},
		},
		{
			name:    "middle match can suppress both neighbors",
			matches: []encodingMatch{match(3, 0, 3), match(2, 3, 6), match(3, 6, 9)},
			want:    []encodingKind{hexKind},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []encodingKind
			var filter encodingMatchFilter
			for _, match := range tt.matches {
				if ready, ok := filter.add(match); ok {
					got = append(got, ready.encoding.kind)
				}
			}
			if ready, ok := filter.finish(); ok {
				got = append(got, ready.encoding.kind)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecoderReleaseClearsStringCache(t *testing.T) {
	decoder := NewDecoder()
	decoded, segments := decoder.Decode("c21hbGwtc2VjcmV0", nil)
	require.Equal(t, "small-secret", decoded)
	require.NotEmpty(t, segments)
	require.NotEmpty(t, decoder.decodedMap)

	decoder.Release()
	require.Empty(t, decoder.decodedMap)
	require.Nil(t, decoder.byteResult)
	require.Nil(t, decoder.ownedSegments)
}

func TestDecoderStartingNewChainReleasesPriorScratch(t *testing.T) {
	decoder := NewDecoder()
	defer decoder.Release()

	_, first := decoder.Decode("c21hbGwtc2VjcmV0", nil)
	require.Len(t, first, 1)
	require.Len(t, *decoder.ownedSegments, 1)

	_, second := decoder.Decode("YW5vdGhlci1zZWNyZXQ=", nil)
	require.Len(t, second, 1)
	// A new top-level call replaces the prior chain instead of accumulating its
	// segment metadata until the caller remembers to invoke Release.
	require.Len(t, *decoder.ownedSegments, 1)
}
