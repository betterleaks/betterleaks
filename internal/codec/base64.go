package codec

import (
	"encoding/base64"
)

// likelyBase64Chars is a set of characters that you would expect to find at
// least one of in base64 encoded data. This risks missing about 1% of
// base64 encoded data that doesn't contain these characters, but gives you
// the performance gain of not trying to decode a lot of long symbols in code.
var likelyBase64Chars = make([]bool, 256)

func init() {
	for _, c := range `0123456789+/-_` {
		likelyBase64Chars[c] = true
	}
}

// decodeBase64 decodes base64 encoded printable ASCII characters
func decodeBase64(encodedValue string) string {
	// Exit early if it doesn't seem like base64
	if !hasByte(encodedValue, likelyBase64Chars) {
		return ""
	}

	// Most candidates are short identifiers that fail decoding. Both attempts
	// can share stack storage; only successful text needs an owned string.
	var scratch [256]byte
	buffer := scratch[:]
	if size := base64.RawURLEncoding.DecodedLen(len(encodedValue)); size > len(buffer) {
		buffer = make([]byte, size)
	}

	// Try standard base64 decoding
	n, err := base64.StdEncoding.Decode(buffer, []byte(encodedValue))
	if err == nil && isPrintableASCII(buffer[:n]) {
		return string(buffer[:n])
	}

	// Try base64url decoding
	n, err = base64.RawURLEncoding.Decode(buffer, []byte(encodedValue))
	if err == nil && isPrintableASCII(buffer[:n]) {
		return string(buffer[:n])
	}

	return ""
}

var base64Values [256]byte

func init() {
	for i := range base64Values {
		base64Values[i] = 0xff
	}
	for i, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		base64Values[c] = byte(i)
	}
	base64Values['-'], base64Values['_'] = 62, 63
}

// One quartet cheaply rejects most non-candidates; longer lookahead did not
// improve scan time. A failed prefix cannot become printable by decoding more.
// Unknown input characters fall back to the normal decoder (which can ignore
// line breaks); discovery calls this on uninterrupted Base64 alphabet runs.
func possibleBase64Prefix(value string) bool {
	if len(value) < 4 {
		return true
	}
	a, b, c, d := base64Values[value[0]], base64Values[value[1]], base64Values[value[2]], base64Values[value[3]]
	if a|b|c|d == 0xff {
		return true
	}
	return printableASCII[a<<2|b>>4] && printableASCII[b<<4|c>>2] && printableASCII[c<<6|d]
}
