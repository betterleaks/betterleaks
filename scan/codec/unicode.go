package codec

import (
	"strings"
	"unicode/utf8"
)

// Unicode characters are encoded as 1 to 4 bytes per rune.
const maxBytesPerRune = 4

// parseHex4 parses exactly 4 hex characters into a rune value.
// Returns the rune and true on success, 0 and false on failure.
func parseHex4(s string, offset int) (rune, bool) {
	if offset+4 > len(s) {
		return 0, false
	}
	var val rune
	for i := 0; i < 4; i++ {
		n := hexMap[s[offset+i]]
		if n == '\xff' {
			return 0, false
		}
		val = val<<4 | rune(n)
	}
	return val, true
}

// decodeUnicode decodes Unicode escape sequences in the given string.
// Handles both U+XXXX code point notation and \uXXXX / \\uXXXX escape sequences.
func decodeUnicode(encodedValue string) string {
	// Determine which format we're dealing with
	if strings.Contains(encodedValue, "U+") {
		return decodeUnicodeCodePoints(encodedValue)
	}
	if strings.Contains(encodedValue, `\u`) || strings.Contains(encodedValue, `\U`) {
		return decodeUnicodeEscapes(encodedValue)
	}
	return encodedValue
}

// decodeUnicodeCodePoints decodes U+XXXX sequences with byte scanning.
func decodeUnicodeCodePoints(s string) string {
	n := len(s)
	var buf strings.Builder
	buf.Grow(n)
	utf8Bytes := make([]byte, maxBytesPerRune)

	i := 0
	changed := false
	for i < n {
		// Look for U+XXXX
		if i+5 < n && s[i] == 'U' && s[i+1] == '+' {
			r, ok := parseHex4(s, i+2)
			if ok {
				changed = true
				utf8Len := utf8.EncodeRune(utf8Bytes, r)
				buf.Write(utf8Bytes[:utf8Len])
				i += 6
				// Skip trailing whitespace/separator between code points
				// The regex matched `U+XXXX.?` where .? consumed a trailing char,
				// and the multi pattern split on whitespace.
				if i < n && (s[i] == ' ' || s[i] == '\t') {
					// Only skip the space if the next thing is another U+XXXX
					// (to avoid eating meaningful trailing spaces)
					if i+6 < n && s[i+1] == 'U' && s[i+2] == '+' {
						i++ // skip separator
					}
				}
				continue
			}
		}
		buf.WriteByte(s[i])
		i++
	}

	if !changed {
		return s
	}
	return buf.String()
}

// decodeUnicodeEscapes decodes \uXXXX and \\uXXXX sequences with byte scanning.
func decodeUnicodeEscapes(s string) string {
	n := len(s)
	var buf strings.Builder
	buf.Grow(n)
	utf8Bytes := make([]byte, maxBytesPerRune)

	i := 0
	changed := false
	for i < n {
		if s[i] == '\\' {
			// Check for \\uXXXX (double backslash + u + 4 hex)
			if i+6 < n && s[i+1] == '\\' {
				uc := s[i+2]
				if uc == 'u' || uc == 'U' {
					r, ok := parseHex4(s, i+3)
					if ok {
						changed = true
						utf8Len := utf8.EncodeRune(utf8Bytes, r)
						buf.Write(utf8Bytes[:utf8Len])
						i += 7
						continue
					}
				}
			}
			// Check for \uXXXX (single backslash + u + 4 hex)
			if i+5 < n {
				uc := s[i+1]
				if uc == 'u' || uc == 'U' {
					r, ok := parseHex4(s, i+2)
					if ok {
						changed = true
						utf8Len := utf8.EncodeRune(utf8Bytes, r)
						buf.Write(utf8Bytes[:utf8Len])
						i += 6
						continue
					}
				}
			}
		}
		buf.WriteByte(s[i])
		i++
	}

	if !changed {
		return s
	}
	return buf.String()
}
