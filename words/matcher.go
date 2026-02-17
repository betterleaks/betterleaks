package words

import (
	_ "embed"
	"errors"
	"hash/crc32"
	"math/bits"
	"os"

	"github.com/klauspost/compress/zstd"
)

// File format: little-endian.
//
// Header (32 bytes):
//
//	0:4   magic "WAC1"
//	4:6   version (uint16) == 1
//	6:8   alphabet (uint16) == 26
//	8:12  stateCount (uint32)
//	12:16 nextCount (uint32)
//	16:18 maxWordLen (uint16)
//	18:20 reserved
//	20:24 statesOffset (uint32) == 32
//	24:28 nextOffset   (uint32) == 32 + stateCount*16
//	28:32 crc32 of bytes [statesOffset : nextOffset+nextCount*4]
//
// State record (16 bytes) repeated stateCount times:
//
//	0:4   child bitmap (uint32) for 'a'..'z'
//	4:8   base index into next array (uint32)
//	8:12  fail state id (uint32)
//	12:14 outMaxLen (uint16) - max pattern length that ends at this state
//	      OR any state on its failure chain.
//	14:16 reserved
//
// Next array: nextCount uint32 values. For each state, children are packed in
// ascending letter order. The rank of a letter in the bitmap selects the child.
const (
	fileMagic     = "WAC1"
	fileVersion   = 1
	alphabetSize  = 26
	headerSize    = 32
	stateRecSize  = 16
	rootStateID   = 0
	stateBitAByte = byte('a')
	stateBitZByte = byte('z')
)

var ErrBadFormat = errors.New("words: bad matcher data format")

//go:embed words_ac.dat.zst
var defaultDataZst []byte

// Default is the package-level matcher loaded from embedded data.
// It panics at init if the embedded data is invalid.
var Default *Matcher

func init() {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		panic("words: init zstd decoder: " + err.Error())
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(defaultDataZst, nil)
	if err != nil {
		panic("words: decompress embedded data: " + err.Error())
	}
	Default = MustLoadMatcher(raw)
}

// Matcher is a read-only Aho-Corasick matcher specialized to ASCII letters a-z.
//
// Runtime properties:
//   - zero allocations per search
//   - single-pass scan per input (amortized O(n))
//   - safe for concurrent use
//
// Behavioral contract:
//   - input is treated as bytes
//   - 'A'..'Z' is lowercased to 'a'..'z'
//   - any non [A-Za-z] resets the automaton to root
type Matcher struct {
	data       []byte
	statesOff  int
	nextOff    int
	stateCount uint32
	nextCount  uint32
	maxWordLen uint16
}

// LoadMatcher validates and returns a matcher that reads directly from data.
// The matcher retains a reference to data; callers must keep it alive.
func LoadMatcher(data []byte) (*Matcher, error) {
	if len(data) < headerSize {
		return nil, ErrBadFormat
	}

	if string(data[0:4]) != fileMagic {
		return nil, ErrBadFormat
	}
	ver := u16(data, 4)
	if ver != fileVersion {
		return nil, ErrBadFormat
	}
	alpha := u16(data, 6)
	if alpha != alphabetSize {
		return nil, ErrBadFormat
	}

	stateCount := u32(data, 8)
	nextCount := u32(data, 12)
	maxWordLen := u16(data, 16)
	statesOff := int(u32(data, 20))
	nextOff := int(u32(data, 24))
	wantCRC := u32(data, 28)

	if statesOff != headerSize {
		return nil, ErrBadFormat
	}

	// Bounds checks using 64-bit math to avoid overflow.
	statesBytes64 := int64(stateCount) * int64(stateRecSize)
	if statesBytes64 < 0 || statesBytes64 > int64(^uint(0)>>1) {
		return nil, ErrBadFormat
	}
	wantNextOff := headerSize + int(statesBytes64)
	if nextOff != wantNextOff {
		return nil, ErrBadFormat
	}

	nextBytes64 := int64(nextCount) * 4
	if nextBytes64 < 0 || nextBytes64 > int64(^uint(0)>>1) {
		return nil, ErrBadFormat
	}
	totalLen := nextOff + int(nextBytes64)
	if totalLen < 0 || totalLen > len(data) {
		return nil, ErrBadFormat
	}

	gotCRC := crc32.ChecksumIEEE(data[statesOff:totalLen])
	if gotCRC != wantCRC {
		return nil, ErrBadFormat
	}

	m := &Matcher{
		data:       data[:totalLen],
		statesOff:  statesOff,
		nextOff:    nextOff,
		stateCount: stateCount,
		nextCount:  nextCount,
		maxWordLen: maxWordLen,
	}

	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// MustLoadMatcher panics if LoadMatcher fails.
func MustLoadMatcher(data []byte) *Matcher {
	m, err := LoadMatcher(data)
	if err != nil {
		panic(err)
	}
	return m
}

// LoadMatcherFromFile reads a matcher file from disk and loads it.
func LoadMatcherFromFile(path string) (*Matcher, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadMatcher(b)
}

// validate checks structural integrity: fail links point within bounds,
// child base+count fits the next array, and root's fail link is self-referencing.
func (m *Matcher) validate() error {
	if m.stateCount == 0 {
		return ErrBadFormat
	}
	if m.stateCount > uint32((m.nextOff-m.statesOff)/stateRecSize) {
		return ErrBadFormat
	}

	for s := uint32(0); s < m.stateCount; s++ {
		mask, base, fail, out := m.stateRec(s)

		if fail >= m.stateCount {
			return ErrBadFormat
		}
		nKids := uint32(bits.OnesCount32(mask))
		if base > m.nextCount {
			return ErrBadFormat
		}
		if base+nKids > m.nextCount {
			return ErrBadFormat
		}
		if out > m.maxWordLen {
			return ErrBadFormat
		}
	}

	// Root fail must be 0.
	_, _, fail0, _ := m.stateRec(rootStateID)
	if fail0 != 0 {
		return ErrBadFormat
	}
	return nil
}

// MaxMatchLenASCII returns the maximum dictionary word length found as a
// substring in s, scanning once with the embedded Aho-Corasick automaton.
//
// stopAt is an early-exit threshold. If stopAt > 0 and a match of length
// >= stopAt is found, the function returns immediately.
func (m *Matcher) MaxMatchLenASCII(s string, stopAt int) int {
	if len(s) == 0 {
		return 0
	}
	if stopAt <= 0 {
		stopAt = int(m.maxWordLen)
	}

	state := uint32(rootStateID)
	maxFound := 0

	for i := 0; i < len(s); i++ {
		c := s[i]

		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c < stateBitAByte || c > stateBitZByte {
			state = rootStateID
			continue
		}
		idx := c - stateBitAByte // 0..25

		// Follow fail links until we can take idx or we reach root.
		for {
			next, ok := m.step(state, idx)
			if ok {
				state = next
				break
			}
			if state == rootStateID {
				break
			}
			state = m.fail(state)
		}

		out := int(m.outMax(state))
		if out > maxFound {
			maxFound = out
			if maxFound >= stopAt {
				return maxFound
			}
		}
	}

	return maxFound
}

// ContainsAnyASCII returns true if s contains any dictionary word with length
// >= minLen.
func (m *Matcher) ContainsAnyASCII(s string, minLen int) bool {
	if minLen <= 0 {
		minLen = 1
	}
	return m.MaxMatchLenASCII(s, minLen) >= minLen
}

// --- internal accessors ---

func (m *Matcher) stateRec(state uint32) (mask uint32, base uint32, fail uint32, out uint16) {
	off := m.statesOff + int(state)*stateRecSize
	mask = u32(m.data, off+0)
	base = u32(m.data, off+4)
	fail = u32(m.data, off+8)
	out = u16(m.data, off+12)
	return
}

func (m *Matcher) fail(state uint32) uint32 {
	off := m.statesOff + int(state)*stateRecSize
	return u32(m.data, off+8)
}

func (m *Matcher) outMax(state uint32) uint16 {
	off := m.statesOff + int(state)*stateRecSize
	return u16(m.data, off+12)
}

// step returns (nextState, true) if there's an outgoing edge labeled idx
// from state, else (0, false). idx is in [0,25].
func (m *Matcher) step(state uint32, idx byte) (uint32, bool) {
	off := m.statesOff + int(state)*stateRecSize
	mask := u32(m.data, off+0)

	bit := uint32(1) << uint32(idx)
	if mask&bit == 0 {
		return 0, false
	}

	base := u32(m.data, off+4)
	rank := bits.OnesCount32(mask & (bit - 1))
	nextIdx := base + uint32(rank)
	nextOff := m.nextOff + int(nextIdx)*4
	return u32(m.data, nextOff), true
}

func u16(b []byte, off int) uint16 {
	_ = b[off+1]
	return uint16(b[off]) | uint16(b[off+1])<<8
}

func u32(b []byte, off int) uint32 {
	_ = b[off+3]
	return uint32(b[off]) |
		uint32(b[off+1])<<8 |
		uint32(b[off+2])<<16 |
		uint32(b[off+3])<<24
}
