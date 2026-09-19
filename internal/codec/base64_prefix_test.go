package codec

import (
	"encoding/base64"
	"testing"
)

func TestBase64PrefixAcceptsPrintableInput(t *testing.T) {
	for b := byte(0); b < 127; b++ {
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
