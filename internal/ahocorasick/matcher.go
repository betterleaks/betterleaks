// Package ahocorasick provides the detector's allocation-free keyword matcher.
// Its Aho-Corasick implementation is derived from github.com/RRethy/ahocorasick
// (MIT); see LICENSE.
package ahocorasick

import (
	"math/bits"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Matcher is a flat Aho-Corasick DFA. Pattern IDs are their input indexes.
// A compiled Matcher is read-only and safe to use from concurrent scans.
type Matcher struct {
	// transitions is a flattened [state][byte class] table. Values are row
	// offsets, so traversal adds the byte class without multiplying the state.
	transitions []uint32
	shift       uint
	classes     [256]byte

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

// outputFlag marks a transition entry whose target state completes at least
// one pattern; stateMask recovers the row offset.
const (
	outputFlag uint32 = 1 << 31
	stateMask         = ^outputFlag
)

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
	// Entries leading to a state with outputs carry outputFlag, so the hot loop
	// consults outputs only there.
	for i, entry := range transitions {
		if len(outputs[entry>>shift]) > 0 {
			transitions[i] = entry | outputFlag
		}
	}
	m := &Matcher{transitions: transitions, shift: shift, outputs: outputs, lengths: lengths, maxLength: maxLength, foldASCII: foldASCII}
	for b := range m.classes {
		m.classes[b] = classes[fold(byte(b), foldASCII)]
	}
	return m
}

// Visit calls fn for every match in ascending end order. Returning false stops
// traversal.
func (m *Matcher) Visit(text string, fn func(patternID, start, end int) bool) {
	if len(text) < twoChainMinBytes || (m.foldASCII && hasASCIIFoldRunes(text)) {
		m.visitOne(text, fn)
		return
	}
	m.visitTwo(text, fn)
}

// visitOne walks the automaton over text with one dependent load chain.
func (m *Matcher) visitOne(text string, fn func(patternID, start, end int) bool) {
	// Local copies let the loop reuse field values across calls to fn.
	transitions, classes, shift, fold := m.transitions, &m.classes, m.shift, m.foldASCII
	state := uint32(0)
	for i := 0; i < len(text); i++ {
		b := text[i]
		if fold && b >= utf8.RuneSelf {
			// Long s and Kelvin sign are the only non-ASCII runes that fold
			// to ASCII. Everything else breaks an ASCII keyword, including
			// malformed UTF-8. No Unicode table lookup is needed here.
			if (b == 0xc5 && i+1 < len(text) && text[i+1] == 0xbf) ||
				(b == 0xe2 && i+2 < len(text) && text[i+1] == 0x84 && text[i+2] == 0xaa) {
				m.visitUnicode(text, i, state, fn)
				return
			}
			state = 0
			continue
		}
		entry := transitions[int(state)+int(classes[b])]
		state = entry & stateMask
		if entry&outputFlag == 0 {
			continue
		}
		for _, id := range m.outputs[state>>shift] {
			if !fn(int(id), i+1-m.lengths[id], i+1) {
				return
			}
		}
	}
}

// twoChainMinBytes is the text length from which two interleaved chains pay
// for the buffered second half: measured 430 vs 290 MB/s at 512 bytes on the
// default keyword set.
const twoChainMinBytes = 256

// hasASCIIFoldRunes reports whether text contains U+017F or U+212A, the runes
// visitUnicode handles.
func hasASCIIFoldRunes(text string) bool {
	return strings.Contains(text, "\u017f") || strings.Contains(text, "\u212a")
}

// pendingMatch is a second-half match held back until the first half has
// reported everything before it.
type pendingMatch struct {
	id  uint32
	end int32
}

var pendingPool = sync.Pool{New: func() any {
	buf := make([]pendingMatch, 0, 1024)
	return &buf
}}

// visitTwo walks two halves of text at once. Each automaton step depends on
// the previous state's table entry, so one chain runs at cache latency per
// byte; two independent chains keep two loads in flight. The second chain
// starts maxLength bytes before the midpoint, which is enough context to reach
// the state the first chain would have at the midpoint, and reports only
// matches ending past it. Its matches are buffered so fn still sees ascending
// end offsets.
func (m *Matcher) visitTwo(text string, fn func(patternID, start, end int) bool) {
	transitions, classes, shift, fold := m.transitions, &m.classes, m.shift, m.foldASCII
	mid := len(text) / 2
	pending := pendingPool.Get().(*[]pendingMatch)
	defer func() {
		*pending = (*pending)[:0]
		pendingPool.Put(pending)
	}()

	stateA, stateB := uint32(0), uint32(0)
	i, j := 0, max(0, mid-m.maxLength)
	step := func(state uint32, b byte) (uint32, bool) {
		if fold && b >= utf8.RuneSelf {
			return 0, false
		}
		entry := transitions[int(state)+int(classes[b])]
		return entry & stateMask, entry&outputFlag != 0
	}
	for i < mid {
		var outA, outB bool
		stateA, outA = step(stateA, text[i])
		stateB, outB = step(stateB, text[j])
		i++
		j++
		if outA {
			for _, id := range m.outputs[stateA>>shift] {
				if !fn(int(id), i-m.lengths[id], i) {
					return
				}
			}
		}
		if outB && j > mid {
			for _, id := range m.outputs[stateB>>shift] {
				*pending = append(*pending, pendingMatch{id: id, end: int32(j)})
			}
		}
	}
	for ; j < len(text); j++ {
		var outB bool
		stateB, outB = step(stateB, text[j])
		if outB {
			for _, id := range m.outputs[stateB>>shift] {
				*pending = append(*pending, pendingMatch{id: id, end: int32(j + 1)})
			}
		}
	}
	for _, p := range *pending {
		end := int(p.end)
		if !fn(int(p.id), end-m.lengths[p.id], end) {
			return
		}
	}
}

// Unicode folding changes the relationship between matcher bytes and source
// bytes. Resume with the original offset-ring algorithm, seeded with the
// ASCII prefix that produced state. The ordinary ASCII path needs no ring.
func (m *Matcher) visitUnicode(text string, offset int, state uint32, fn func(patternID, start, end int) bool) {
	var localStarts [128]int
	starts := localStarts[:]
	if m.maxLength > len(starts) {
		starts = make([]int, m.maxLength)
	}
	position := offset
	for i := max(0, offset-m.maxLength); i < offset; i++ {
		starts[i%len(starts)] = i
	}

	for i := offset; i < len(text); {
		b := text[i]
		size := 1
		if m.foldASCII && b >= utf8.RuneSelf {
			r, runeSize := utf8.DecodeRuneInString(text[i:])
			folded, ok := foldRuneASCII(r)
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
		state = m.transitions[int(state)+int(m.classes[b])] & stateMask
		for _, id := range m.outputs[state>>m.shift] {
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

// foldRuneASCII reports the ASCII member of a rune's Unicode simple-fold set.
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
