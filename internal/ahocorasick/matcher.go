// Package ahocorasick provides the detector's allocation-free keyword matcher.
// Its Aho-Corasick implementation is derived from github.com/RRethy/ahocorasick
// (MIT); see LICENSE.
package ahocorasick

import "unicode/utf8"

// Matcher is a flat Aho-Corasick DFA. Pattern IDs are their input indexes.
// A compiled Matcher is read-only and safe to use from concurrent scans.
type Matcher struct {
	// transitions is a flattened [state][byte] table. Every entry is populated,
	// including failure transitions, so Visit needs one lookup per input byte.
	transitions []uint32

	// outputs lists the pattern IDs completed at each state. It includes outputs
	// inherited through failure links, which is how overlapping matches are found.
	outputs [][]uint32

	// lengths stores each pattern's matcher-byte length, indexed by pattern ID.
	// Visit uses it to recover the source start offset of a completed match.
	lengths []int

	// maxLength bounds the source-offset ring used by Visit.
	maxLength int

	// foldASCII makes ASCII matching case-insensitive. Visit also recognizes
	// Unicode runes whose simple-fold set contains an ASCII byte.
	foldASCII bool
}

type node struct {
	next map[byte]uint32
	fail uint32
	out  []uint32
}

// Compile builds a matcher. When foldASCII is true, ASCII case is ignored.
func Compile(patterns []string, foldASCII bool) *Matcher {
	nodes := []node{{next: make(map[byte]uint32)}}
	lengths := make([]int, len(patterns))
	maxLength := 0
	for id, pattern := range patterns {
		state := uint32(0)
		lengths[id] = len(pattern)
		maxLength = max(maxLength, len(pattern))
		for i := 0; i < len(pattern); i++ {
			b := fold(pattern[i], foldASCII)
			next, ok := nodes[state].next[b]
			if !ok {
				next = uint32(len(nodes))
				nodes[state].next[b] = next
				nodes = append(nodes, node{next: make(map[byte]uint32)})
			}
			state = next
		}
		nodes[state].out = append(nodes[state].out, uint32(id))
	}

	// A dense table costs more memory than maps, but lets Visit advance with one
	// indexed lookup per byte. Fill missing edges from each state's failure state
	// so the scan never has to walk the failure chain.
	transitions := make([]uint32, len(nodes)*256)
	queue := make([]uint32, 0, len(nodes))
	for b, child := range nodes[0].next {
		transitions[int(b)] = child
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		fail := nodes[state].fail
		if inherited := nodes[fail].out; len(inherited) > 0 {
			nodes[state].out = append(nodes[state].out, inherited...)
		}
		base := int(state) * 256
		failBase := int(fail) * 256
		for b := range 256 {
			if child, ok := nodes[state].next[byte(b)]; ok {
				nodes[child].fail = transitions[failBase+b]
				transitions[base+b] = child
				queue = append(queue, child)
			} else {
				transitions[base+b] = transitions[failBase+b]
			}
		}
	}

	outputs := make([][]uint32, len(nodes))
	for i := range nodes {
		outputs[i] = nodes[i].out
	}
	return &Matcher{transitions: transitions, outputs: outputs, lengths: lengths, maxLength: maxLength, foldASCII: foldASCII}
}

// Visit calls fn for every match. Returning false stops traversal.
func (m *Matcher) Visit(text string, fn func(patternID, start, end int) bool) {
	state := uint32(0)
	var localStarts [128]int
	starts := localStarts[:]
	if m.maxLength > len(starts) {
		starts = make([]int, m.maxLength)
	}
	position := 0

	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRuneInString(text[i:])
			folded, ok := FoldRuneASCII(r)
			if !ok {
				state = 0
				i += runeSize
				continue
			}
			b, size = folded, runeSize
		} else {
			b = fold(b, m.foldASCII)
		}

		// Patterns are measured in matcher bytes, while a Unicode rune that folds
		// to ASCII occupies multiple source bytes. Keep the source start of the
		// last maxLength matcher bytes so callbacks still receive byte offsets.
		starts[position%len(starts)] = i
		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			end := i + size
			start := end
			if length := m.lengths[id]; length > 0 {
				start = starts[(position+1-length)%len(starts)]
			}
			if !fn(int(id), start, end) {
				return
			}
		}
		position++
		i += size
	}
}

// VisitBytes is the byte-slice form of Visit. It preserves byte offsets and
// Unicode simple-fold behavior without materializing an immutable string.
func (m *Matcher) VisitBytes(text []byte, fn func(patternID, start, end int) bool) {
	state := uint32(0)
	var localStarts [128]int
	starts := localStarts[:]
	if m.maxLength > len(starts) {
		starts = make([]int, m.maxLength)
	}
	position := 0

	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRune(text[i:])
			folded, ok := FoldRuneASCII(r)
			if !ok {
				state = 0
				i += runeSize
				continue
			}
			b, size = folded, runeSize
		} else {
			b = fold(b, m.foldASCII)
		}

		starts[position%len(starts)] = i
		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			end := i + size
			start := end
			if length := m.lengths[id]; length > 0 {
				start = starts[(position+1-length)%len(starts)]
			}
			if !fn(int(id), start, end) {
				return
			}
		}
		position++
		i += size
	}
}

// VisitIDs calls fn with the ID of every matched pattern. It omits source
// offset bookkeeping for prefilters that only need to select candidate rules.
func (m *Matcher) VisitIDs(text string, fn func(patternID int) bool) {
	state := uint32(0)
	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRuneInString(text[i:])
			folded, ok := FoldRuneASCII(r)
			if !ok {
				state = 0
				i += runeSize
				continue
			}
			b, size = folded, runeSize
		} else {
			b = fold(b, m.foldASCII)
		}

		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			if !fn(int(id)) {
				return
			}
		}
		i += size
	}
}

// VisitIDsBytes is the byte-slice form of VisitIDs.
func (m *Matcher) VisitIDsBytes(text []byte, fn func(patternID int) bool) {
	state := uint32(0)
	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRune(text[i:])
			folded, ok := FoldRuneASCII(r)
			if !ok {
				state = 0
				i += runeSize
				continue
			}
			b, size = folded, runeSize
		} else {
			b = fold(b, m.foldASCII)
		}

		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			if !fn(int(id)) {
				return
			}
		}
		i += size
	}
}

// VisitEnds calls fn with the pattern ID and source-byte end offset of every
// match. It is cheaper than Visit when callers need a conservative window but
// do not need the exact start offset.
func (m *Matcher) VisitEnds(text string, fn func(patternID, end int) bool) {
	state := uint32(0)
	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRuneInString(text[i:])
			folded, ok := FoldRuneASCII(r)
			if !ok {
				state = 0
				i += runeSize
				continue
			}
			b, size = folded, runeSize
		} else {
			b = fold(b, m.foldASCII)
		}

		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			if !fn(int(id), i+size) {
				return
			}
		}
		i += size
	}
}

// VisitEndsBytes is the byte-slice form of VisitEnds.
func (m *Matcher) VisitEndsBytes(text []byte, fn func(patternID, end int) bool) {
	state := uint32(0)
	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRune(text[i:])
			folded, ok := FoldRuneASCII(r)
			if !ok {
				state = 0
				i += runeSize
				continue
			}
			b, size = folded, runeSize
		} else {
			b = fold(b, m.foldASCII)
		}

		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			if !fn(int(id), i+size) {
				return
			}
		}
		i += size
	}
}

// FoldRuneASCII reports the ASCII member of a non-ASCII rune's Unicode
// simple-fold set. Unicode has exactly two such compatibility folds: long s
// and Kelvin sign. Keeping them explicit avoids consulting the Unicode case
// tables for every ordinary non-ASCII source rune.
func FoldRuneASCII(r rune) (byte, bool) {
	switch r {
	case '\u017f': // long s: S, s, ſ
		return 's', true
	case '\u212a': // Kelvin sign: K, k, K
		return 'k', true
	default:
		return 0, false
	}
}

func fold(b byte, enabled bool) byte {
	if enabled && b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
