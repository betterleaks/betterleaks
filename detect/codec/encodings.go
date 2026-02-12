package codec

import (
	"math"
)

// Lookup tables for byte classification.
var (
	isHexChar    [256]bool // 0-9, A-F, a-f
	isB64Char    [256]bool // 0-9, A-Z, a-z, _, /, +, -  (matches [\w\/+-])
	isB64NotHex  [256]bool // b64 chars that are NOT hex (G-Z, g-z, _, /, +, -)
	isWhitespace [256]bool // space, tab, \n, \r, etc.
)

func init() {
	for c := '0'; c <= '9'; c++ {
		isHexChar[c] = true
		isB64Char[c] = true
	}
	for c := 'A'; c <= 'F'; c++ {
		isHexChar[c] = true
		isB64Char[c] = true
	}
	for c := 'a'; c <= 'f'; c++ {
		isHexChar[c] = true
		isB64Char[c] = true
	}
	for c := 'G'; c <= 'Z'; c++ {
		isB64Char[c] = true
		isB64NotHex[c] = true
	}
	for c := 'g'; c <= 'z'; c++ {
		isB64Char[c] = true
		isB64NotHex[c] = true
	}
	isB64Char['_'] = true
	isB64NotHex['_'] = true
	isB64Char['/'] = true
	isB64NotHex['/'] = true
	isB64Char['+'] = true
	isB64NotHex['+'] = true
	isB64Char['-'] = true
	isB64NotHex['-'] = true

	isWhitespace[' '] = true
	isWhitespace['\t'] = true
	isWhitespace['\n'] = true
	isWhitespace['\r'] = true
	isWhitespace['\f'] = true
	isWhitespace['\v'] = true
}

var (
	encodings = []*encoding{
		{
			kind:       percentKind,
			decode:     decodePercent,
			precedence: 4,
		},
		{
			kind:       unicodeKind,
			decode:     decodeUnicode,
			precedence: 3,
		},
		{
			kind:       hexKind,
			decode:     decodeHex,
			precedence: 2,
		},
		{
			kind:       base64Kind,
			decode:     decodeBase64,
			precedence: 1,
		},
	}
)

// encodingNames is used to map the encodingKinds to their name
var encodingNames = []string{
	"percent",
	"unicode",
	"hex",
	"base64",
}

// encodingKind can be or'd together to capture all of the unique encodings
// that were present in a segment
type encodingKind int

var (
	// make sure these go up by powers of 2
	percentKind = encodingKind(1)
	unicodeKind = encodingKind(2)
	hexKind     = encodingKind(4)
	base64Kind  = encodingKind(8)
)

func (e encodingKind) String() string {
	i := int(math.Log2(float64(e)))
	if i >= len(encodingNames) {
		return ""
	}
	return encodingNames[i]
}

// kinds returns a list of encodingKinds combined in this one
func (e encodingKind) kinds() []encodingKind {
	kinds := []encodingKind{}

	for i := 0; i < len(encodingNames); i++ {
		if kind := int(e) & int(math.Pow(2, float64(i))); kind != 0 {
			kinds = append(kinds, encodingKind(kind))
		}
	}

	return kinds
}

// encodingMatch represents a match of an encoding in the text
type encodingMatch struct {
	encoding *encoding
	startEnd
}

// encoding represent a type of coding supported by the decoder.
type encoding struct {
	// the kind of decoding (e.g. base64, etc)
	kind encodingKind
	// take the match and return the decoded value
	decode func(string) string
	// determine which encoding should win out when two overlap
	precedence int
}

// findEncodingMatches finds as many encodings as it can for this pass
// using a single-pass byte-level scanner instead of regex.
func findEncodingMatches(data string) []encodingMatch {
	n := len(data)
	if n == 0 {
		return nil
	}

	var all []encodingMatch
	i := 0

	for i < n {
		c := data[i]

		// --- Percent encoding: %XX ---
		if c == '%' && i+2 < n && isHexChar[data[i+1]] && isHexChar[data[i+2]] {
			start := i
			// Scan forward to find the last %XX on this line.
			// The regex `%XX(?:.*%XX)?` is greedy and matches from the first
			// %XX through any chars (except \n) to the last %XX on the line.
			lastPercentEnd := i + 3
			j := i + 3
			for j < n && data[j] != '\n' {
				if data[j] == '%' && j+2 < n && isHexChar[data[j+1]] && isHexChar[data[j+2]] {
					lastPercentEnd = j + 3
				}
				j++
			}
			all = append(all, encodingMatch{
				encoding: encodings[0], // percent
				startEnd: startEnd{start, lastPercentEnd},
			})
			i = lastPercentEnd
			continue
		}

		// --- Unicode code points: U+XXXX ---
		if c == 'U' && i+5 < n && data[i+1] == '+' &&
			isHexChar[data[i+2]] && isHexChar[data[i+3]] &&
			isHexChar[data[i+4]] && isHexChar[data[i+5]] {
			// Check that the next char after the 4 hex digits is whitespace or end.
			// The regex requires (?:\s|$) after each U+XXXX.
			afterHex := i + 6
			if afterHex >= n || isWhitespace[data[afterHex]] {
				start := i
				end := afterHex
				// Consume additional U+XXXX sequences separated by whitespace
				j := afterHex
				for j < n {
					// Skip whitespace between code points
					if !isWhitespace[data[j]] {
						break
					}
					ws := j
					for ws < n && isWhitespace[data[ws]] {
						ws++
					}
					// Check for another U+XXXX
					if ws+5 < n && data[ws] == 'U' && data[ws+1] == '+' &&
						isHexChar[data[ws+2]] && isHexChar[data[ws+3]] &&
						isHexChar[data[ws+4]] && isHexChar[data[ws+5]] {
						nextAfter := ws + 6
						if nextAfter >= n || isWhitespace[data[nextAfter]] {
							end = nextAfter
							j = nextAfter
							continue
						}
					}
					break
				}
				all = append(all, encodingMatch{
					encoding: encodings[1], // unicode
					startEnd: startEnd{start, end},
				})
				i = end
				continue
			}
		}

		// --- Unicode escapes: \uXXXX or \\uXXXX ---
		if c == '\\' {
			matched := false
			// Check for \\uXXXX (double backslash)
			if i+7 < n && data[i+1] == '\\' {
				uc := data[i+2]
				if (uc == 'u' || uc == 'U') &&
					isHexChar[data[i+3]] && isHexChar[data[i+4]] &&
					isHexChar[data[i+5]] && isHexChar[data[i+6]] {
					start := i
					end := i + 7
					// Consume additional \\uXXXX or \uXXXX sequences
					j := end
					for j < n {
						if j+6 < n && data[j] == '\\' && data[j+1] == '\\' {
							uc2 := data[j+2]
							if (uc2 == 'u' || uc2 == 'U') &&
								isHexChar[data[j+3]] && isHexChar[data[j+4]] &&
								isHexChar[data[j+5]] && isHexChar[data[j+6]] {
								end = j + 7
								j = end
								continue
							}
						}
						if j+5 < n && data[j] == '\\' {
							uc2 := data[j+1]
							if (uc2 == 'u' || uc2 == 'U') &&
								isHexChar[data[j+2]] && isHexChar[data[j+3]] &&
								isHexChar[data[j+4]] && isHexChar[data[j+5]] {
								end = j + 6
								j = end
								continue
							}
						}
						break
					}
					all = append(all, encodingMatch{
						encoding: encodings[1], // unicode
						startEnd: startEnd{start, end},
					})
					i = end
					matched = true
				}
			}
			// Check for \uXXXX (single backslash)
			if !matched && i+5 < n {
				uc := data[i+1]
				if (uc == 'u' || uc == 'U') &&
					isHexChar[data[i+2]] && isHexChar[data[i+3]] &&
					isHexChar[data[i+4]] && isHexChar[data[i+5]] {
					start := i
					end := i + 6
					// Consume additional \uXXXX or \\uXXXX sequences
					j := end
					for j < n {
						if j+6 < n && data[j] == '\\' && data[j+1] == '\\' {
							uc2 := data[j+2]
							if (uc2 == 'u' || uc2 == 'U') &&
								isHexChar[data[j+3]] && isHexChar[data[j+4]] &&
								isHexChar[data[j+5]] && isHexChar[data[j+6]] {
								end = j + 7
								j = end
								continue
							}
						}
						if j+5 < n && data[j] == '\\' {
							uc2 := data[j+1]
							if (uc2 == 'u' || uc2 == 'U') &&
								isHexChar[data[j+2]] && isHexChar[data[j+3]] &&
								isHexChar[data[j+4]] && isHexChar[data[j+5]] {
								end = j + 6
								j = end
								continue
							}
						}
						break
					}
					all = append(all, encodingMatch{
						encoding: encodings[1], // unicode
						startEnd: startEnd{start, end},
					})
					i = end
					matched = true
				}
			}
			if matched {
				continue
			}
		}

		// --- Hex / Base64 runs ---
		if isB64Char[c] {
			start := i
			allHex := !isB64NotHex[c]
			i++
			for i < n && isB64Char[data[i]] {
				if isB64NotHex[data[i]] {
					allHex = false
				}
				i++
			}
			runLen := i - start
			end := i

			// Count trailing '=' (up to 2) for base64 padding
			eqCount := 0
			for eqCount < 2 && end < n && data[end] == '=' {
				eqCount++
				end++
			}

			if allHex && runLen >= 32 {
				// Emit as hex match (without trailing =)
				all = append(all, encodingMatch{
					encoding: encodings[2], // hex
					startEnd: startEnd{start, start + runLen},
				})
			} else if runLen >= 16 {
				// Emit as base64 match (include trailing =)
				all = append(all, encodingMatch{
					encoding: encodings[3], // base64
					startEnd: startEnd{start, end},
				})
			}
			continue
		}

		i++
	}

	totalMatches := len(all)
	if totalMatches <= 1 {
		return all
	}

	// filter out lower precedence ones that overlap their neighbors
	filtered := make([]encodingMatch, 0, len(all))
	for i, m := range all {
		if i > 0 {
			prev := all[i-1]
			if m.overlaps(prev.startEnd) && prev.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		if i+1 < totalMatches {
			next := all[i+1]
			if m.overlaps(next.startEnd) && next.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		filtered = append(filtered, m)
	}

	return filtered
}
