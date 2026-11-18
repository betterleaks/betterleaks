// Package ahocorasick provides the detector's allocation-free keyword matcher.
// Its Aho-Corasick implementation is derived from github.com/RRethy/ahocorasick
// (MIT); see LICENSE.
package ahocorasick

import (
	"math/bits"
	"strings"
	"unicode/utf8"
)

const (
	longS      = "ſ"
	kelvinSign = "K"
)

// Matcher is a flat Aho-Corasick DFA. Pattern IDs are their input indexes.
// A compiled Matcher is read-only and safe to use from concurrent scans.
type Matcher struct {
	// transitions is a flattened [state][byte class] table. Values are row
	// offsets, so traversal adds the byte class without multiplying the state.
	transitions []uint32
	shift       uint
	classes     [256]byte
	prefixPairs *prefixPairs

	// outputs lists the pattern IDs completed at each state. It includes outputs
	// inherited through failure links, which is how overlapping matches are found.
	outputs [][]uint32

	// lengths stores each pattern's matcher-byte length, indexed by pattern ID.
	// Visit uses it to recover the source start offset of a completed match.
	lengths   []int
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

	var alphabet [256]bool
	for id, pattern := range patterns {
		state := uint32(0)
		lengths[id] = len(pattern)
		maxLength = max(maxLength, len(pattern))
		for i := 0; i < len(pattern); i++ {
			b := fold(pattern[i], foldASCII)
			alphabet[b] = true
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

	// All bytes absent from the patterns share a failure column. Each used
	// byte gets its own column. ASCII case folding is baked into the lookup.
	var classes [256]byte
	var representatives []byte
	for b, used := range alphabet {
		if !used {
			representatives = append(representatives, byte(b))
			break
		}
	}
	for b, used := range alphabet {
		if used {
			classes[b] = byte(len(representatives))
			representatives = append(representatives, byte(b))
		}
	}
	shift := uint(bits.Len(uint(len(representatives) - 1)))
	width := 1 << shift
	transitions := make([]uint32, len(nodes)*width)
	queue := make([]uint32, 0, len(nodes))
	for b, child := range nodes[0].next {
		transitions[classes[b]] = child << shift
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		fail := nodes[state].fail
		if inherited := nodes[fail].out; len(inherited) > 0 {
			nodes[state].out = append(nodes[state].out, inherited...)
		}
		base := int(state) * width
		failBase := int(fail) * width
		for class, b := range representatives {
			if child, ok := nodes[state].next[b]; ok {
				nodes[child].fail = transitions[failBase+class] >> shift
				transitions[base+class] = child << shift
				queue = append(queue, child)
			} else {
				transitions[base+class] = transitions[failBase+class]
			}
		}
	}

	outputs := make([][]uint32, len(nodes))
	for i := range nodes {
		outputs[i] = nodes[i].out
	}
	m := &Matcher{transitions: transitions, shift: shift, outputs: outputs, lengths: lengths, maxLength: maxLength, foldASCII: foldASCII}
	for b := range m.classes {
		m.classes[b] = classes[fold(byte(b), foldASCII)]
	}
	m.prefixPairs = compilePrefixPairs(patterns, foldASCII)
	return m
}

// Visit calls fn for every match. Returning false stops traversal.
func (m *Matcher) Visit(text string, fn func(patternID, start, end int) bool) {
	state := uint32(0)
	var largeStarts []int
	// Sample periodically so dense source text gets a tight DFA loop while
	// sparse stretches can skip pairs. Sampling never changes eligibility.
	nextSample := 0
	sparse := false
	for i := 0; i < len(text); {
		if i >= nextSample {
			nextSample = i + min(4096, len(text)-i)
			sparse = m.prefixPairs != nil && !m.prefixPairs.dense(text[i:nextSample])
		}
		end := nextSample
		if sparse {
			if state == 0 {
				i += m.prefixPairs.skip(text[i:])
			}
			// Consume the two possible starts checked by the last pair probe.
			end = i + min(2, len(text)-i)
		}
		for i < end {
			b := text[i]
			if m.foldASCII && b >= utf8.RuneSelf {
				if strings.HasPrefix(text[i:], longS) || strings.HasPrefix(text[i:], kelvinSign) {
					i, state = m.visitUnicode(text, i, state, &largeStarts, fn)
				} else {
					state = 0
					i++
				}
				continue
			}
			i++
			state = m.transitions[int(state)+int(m.classes[b])]
			for _, id := range m.outputs[state>>m.shift] {
				if !fn(int(id), i-m.lengths[id], i) {
					return
				}
			}
		}
	}
}

// Track source offsets while a live prefix can contain a multi-byte fold.
// Return to byte traversal as soon as all subsequent starts are ASCII again.
func (m *Matcher) visitUnicode(text string, offset int, state uint32, largeStarts *[]int, fn func(int, int, int) bool) (int, uint32) {
	var localStarts [128]int
	starts := localStarts[:]
	if m.maxLength > len(starts) {
		if *largeStarts == nil {
			*largeStarts = make([]int, m.maxLength)
		}
		starts = *largeStarts
	}
	lastFoldEnd := offset
	position := 0
	for i := offset; i < len(text); {
		start := i
		b := text[i]
		if b < utf8.RuneSelf {
			i++
		} else {
			switch {
			case strings.HasPrefix(text[i:], longS):
				b = 's'
				i += len(longS)
			case strings.HasPrefix(text[i:], kelvinSign):
				b = 'k'
				i += len(kelvinSign)
			default:
				return i + 1, 0
			}
			lastFoldEnd = i
		}
		starts[position%len(starts)] = start
		position++
		state = m.transitions[int(state)+int(m.classes[b])]
		for _, id := range m.outputs[state>>m.shift] {
			pos := position - m.lengths[id]
			// The prefix before offset was consumed one source byte at a time.
			matchStart := offset + pos
			if pos == position {
				matchStart = i // empty pattern
			} else if pos >= 0 {
				matchStart = starts[pos%len(starts)]
			}
			if !fn(int(id), matchStart, i) {
				return len(text), 0
			}
		}
		if state == 0 || i-lastFoldEnd >= m.maxLength {
			return i, state
		}
	}
	return len(text), state
}

func fold(b byte, enabled bool) byte {
	if enabled && b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
