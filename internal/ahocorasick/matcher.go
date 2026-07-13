// Package ahocorasick provides the detector's allocation-free keyword matcher.
// Its Aho-Corasick implementation is derived from github.com/RRethy/ahocorasick
// (MIT); see LICENSE.
package ahocorasick

import (
	"unicode"
	"unicode/utf8"
)

// Matcher is a flat Aho-Corasick DFA. Pattern IDs are their input indexes.
type Matcher struct {
	transitions []uint32
	outputs     [][]uint32
	lengths     []int
	maxLength   int
	foldASCII   bool
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
	var localExtras [128]uint8
	extras := localExtras[:]
	if m.maxLength > len(extras) {
		extras = make([]uint8, m.maxLength)
	}
	correctionRemaining := 0
	correctionPos := -1

	for i := 0; i < len(text); {
		b := text[i]
		size := 1
		extra := 0
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRuneInString(text[i:])
			folded, ok := foldRuneASCII(r)
			if !ok {
				state = 0
				correctionRemaining = 0
				i += runeSize
				continue
			}
			b, size, extra = folded, runeSize, runeSize-1
			if correctionRemaining == 0 {
				clear(extras)
				correctionPos = -1
			}
			correctionRemaining = m.maxLength
		} else {
			b = fold(b, m.foldASCII)
		}

		if correctionRemaining > 0 {
			correctionPos++
			extras[correctionPos%len(extras)] = uint8(extra)
		}
		state = m.transitions[int(state)*256+int(b)]
		for _, id := range m.outputs[state] {
			end := i + size
			start := end - m.lengths[id]
			if correctionRemaining > 0 {
				for j := 0; j < m.lengths[id]; j++ {
					pos := correctionPos - j
					if pos >= 0 {
						start -= int(extras[pos%len(extras)])
					}
				}
			}
			if !fn(int(id), start, end) {
				return
			}
		}
		if correctionRemaining > 0 {
			correctionRemaining--
		}
		i += size
	}
}

func foldRuneASCII(r rune) (byte, bool) {
	for next := r; ; next = unicode.SimpleFold(next) {
		if next < utf8.RuneSelf {
			return fold(byte(next), true), true
		}
		if folded := unicode.SimpleFold(next); folded == r {
			return 0, false
		}
	}
}

func fold(b byte, enabled bool) byte {
	if enabled && b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
