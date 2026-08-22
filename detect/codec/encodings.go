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
			kind:        percentKind,
			decode:      decodePercent,
			decodeBytes: decodePercentBytes,
			precedence:  4,
		},
		{
			kind:        unicodeKind,
			decode:      decodeUnicode,
			decodeBytes: decodeUnicodeBytes,
			precedence:  3,
		},
		{
			kind:        hexKind,
			decode:      decodeHex,
			decodeBytes: decodeHexBytes,
			precedence:  2,
		},
		{
			kind:        base64Kind,
			decode:      decodeBase64,
			decodeBytes: decodeBase64Bytes,
			precedence:  1,
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

	for i := range encodingNames {
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
	// decodeBytes avoids converting every byte-oriented lookalike to a string.
	decodeBytes func([]byte) string
	// determine which encoding should win out when two overlap
	precedence int
}

// encodingMatchFilter applies the same immediate-neighbor precedence rules as
// the former post-processing slice. Keeping one pending match provides the
// necessary lookahead without retaining every base64-like token in a fragment.
type encodingMatchFilter struct {
	pending    encodingMatch
	hasPending bool
	suppressed bool
}

func (f *encodingMatchFilter) add(match encodingMatch) (encodingMatch, bool) {
	if !f.hasPending {
		f.pending = match
		f.hasPending = true
		return encodingMatch{}, false
	}

	ready := f.pending
	nextSuppressesPending := f.pending.overlaps(match.startEnd) &&
		match.encoding.precedence > f.pending.encoding.precedence
	emit := !f.suppressed && !nextSuppressesPending

	f.suppressed = match.overlaps(f.pending.startEnd) &&
		f.pending.encoding.precedence > match.encoding.precedence
	f.pending = match
	return ready, emit
}

func (f *encodingMatchFilter) finish() (encodingMatch, bool) {
	return f.pending, f.hasPending && !f.suppressed
}

// visitEncodingMatches sends every precedence-filtered encoding match to a
// decoder collector using a single-pass byte-level scanner instead of regex.
type encodingText interface {
	string | []byte
}

type encodingMatchCollector interface {
	add(match encodingMatch)
}

func visitEncodingMatches[T encodingText, C encodingMatchCollector](data T, collector C) {
	n := len(data)
	if n == 0 {
		return
	}

	var matches encodingMatchFilter
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
			if ready, ok := matches.add(encodingMatch{
				encoding: encodings[0], // percent
				startEnd: startEnd{start, lastPercentEnd},
			}); ok {
				collector.add(ready)
			}
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
				if ready, ok := matches.add(encodingMatch{
					encoding: encodings[1], // unicode
					startEnd: startEnd{start, end},
				}); ok {
					collector.add(ready)
				}
				i = end
				continue
			}
		}

		// --- Unicode escapes: \uXXXX or \\uXXXX ---
		if c == '\\' {
			matched := false
			// Check for \\uXXXX (double backslash)
			if i+6 < n && data[i+1] == '\\' {
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
					if ready, ok := matches.add(encodingMatch{
						encoding: encodings[1], // unicode
						startEnd: startEnd{start, end},
					}); ok {
						collector.add(ready)
					}
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
					if ready, ok := matches.add(encodingMatch{
						encoding: encodings[1], // unicode
						startEnd: startEnd{start, end},
					}); ok {
						collector.add(ready)
					}
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
				if ready, ok := matches.add(encodingMatch{
					encoding: encodings[2], // hex
					startEnd: startEnd{start, start + runLen},
				}); ok {
					collector.add(ready)
				}
			} else if runLen >= 16 {
				// Emit as base64 match (include trailing =)
				if ready, ok := matches.add(encodingMatch{
					encoding: encodings[3], // base64
					startEnd: startEnd{start, end},
				}); ok {
					collector.add(ready)
				}
			}
			continue
		}

		i++
	}

	if ready, ok := matches.finish(); ok {
		collector.add(ready)
	}
}
