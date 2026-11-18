package ahocorasick

import (
	"encoding/binary"
	"slices"
)

type prefixPairs [1 << 16]byte

// A three-byte prefix starting at i or i+1 must contain the pair at i+1.
// Check four independent pairs at a time to skip eight impossible starts
// without fetching a DFA transition for each byte.
func compilePrefixPairs(patterns []string, foldASCII bool) *prefixPairs {
	if len(patterns) == 0 || slices.ContainsFunc(patterns, func(p string) bool { return len(p) < 3 }) {
		return nil
	}
	pairs := new(prefixPairs)
	for _, p := range patterns {
		for i := range 2 {
			a, b := fold(p[i], foldASCII), fold(p[i+1], foldASCII)
			pairs[uint16(a)|uint16(b)<<8] = 1
		}
	}
	if !foldASCII {
		return pairs
	}
	for i := range pairs {
		a, b := fold(byte(i), true), fold(byte(i>>8), true)
		pairs[i] = pairs[uint16(a)|uint16(b)<<8]
	}
	// A folded s or k can expand to multiple source bytes. Admit every
	// pair inside its UTF-8 encoding or crossing one of its endpoints.
	for _, encoding := range []string{longS, kelvinSign} {
		for i := 1; i < len(encoding); i++ {
			pairs[binary.LittleEndian.Uint16([]byte(encoding[i-1:i+1]))] = 1
		}
		for b := range 256 {
			pairs[b|int(encoding[0])<<8] = 1
			pairs[int(encoding[len(encoding)-1])|b<<8] = 1
		}
	}
	return pairs
}

func (pairs *prefixPairs) skip(text string) int {
	i := 0
	for len(text)-i >= 9 {
		word := binary.LittleEndian.Uint64([]byte(text[i+1 : i+9]))
		if pairs[uint16(word)]|pairs[uint16(word>>16)]|pairs[uint16(word>>32)]|pairs[uint16(word>>48)] != 0 {
			break
		}
		i += 8
	}
	for len(text)-i >= 3 && pairs[binary.LittleEndian.Uint16([]byte(text[i+1:i+3]))] == 0 {
		i += 2
	}
	return i
}

// Sample the next 64 bytes. The result only sets the interval between
// probes; the DFA still consumes every byte in that interval.
func (pairs *prefixPairs) dense(text string) bool {
	if len(text) < 64 {
		return true
	}
	var hits int
	for i := 0; i < 64; i += 4 {
		hits += int(pairs[binary.LittleEndian.Uint16([]byte(text[i:i+2]))])
	}
	return hits >= 4
}
