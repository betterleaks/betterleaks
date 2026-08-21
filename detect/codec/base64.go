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
	return decodeBase64Bytes([]byte(encodedValue))
}

func decodeBase64Bytes(encodedValue []byte) string {
	// Exit early if it doesn't seem like base64
	if !hasByte(encodedValue, likelyBase64Chars) {
		return ""
	}

	// Most candidates are short identifiers that turn out not to be base64.
	// DecodeString allocates an output slice before it can reject them, which
	// creates millions of tiny allocations on a repository-scale scan. Keep the
	// common case on the stack and allocate only for unusually large candidates.
	decodedLen := base64.StdEncoding.DecodedLen(len(encodedValue))
	if rawLen := base64.RawURLEncoding.DecodedLen(len(encodedValue)); rawLen > decodedLen {
		decodedLen = rawLen
	}
	var local [128]byte
	var decodedValue []byte
	if decodedLen <= len(local) {
		decodedValue = local[:decodedLen]
	} else {
		decodedValue = make([]byte, decodedLen)
	}
	// Try standard base64 decoding
	n, err := base64.StdEncoding.Decode(decodedValue, encodedValue)
	if err == nil && isPrintableASCII(decodedValue[:n]) {
		return string(decodedValue[:n])
	}

	// Try base64url decoding
	n, err = base64.RawURLEncoding.Decode(decodedValue, encodedValue)
	if err == nil && isPrintableASCII(decodedValue[:n]) {
		return string(decodedValue[:n])
	}

	return ""
}
