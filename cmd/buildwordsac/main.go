package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"sort"
	"strings"
)

const (
	fileMagic    = "WAC1"
	fileVersion  = 1
	alphabetSize = 26
	headerSize   = 32
	stateRecSize = 16
)

type node struct {
	next    [alphabetSize]uint32 // 0 means absent, else childID+1
	fail    uint32
	termMax uint16
	outMax  uint16
}

type stats struct {
	Lines        int
	Accepted     int
	SkippedEmpty int
	SkippedShort int
	SkippedBad   int
	Deduped      int
	MaxWordLen   int
	StateCount   int
	NextCount    int
	OutputBytes  int
}

func main() {
	var inPath string
	var outPath string
	var strict bool
	var minLen int
	var quiet bool

	flag.StringVar(&inPath, "input", "", "path to newline-delimited word list")
	flag.StringVar(&outPath, "output", "", "output .dat path")
	flag.BoolVar(&strict, "strict", false, "fail on any non [A-Za-z] word")
	flag.IntVar(&minLen, "minlen", 3, "ignore words shorter than this")
	flag.BoolVar(&quiet, "quiet", false, "suppress stats")
	flag.Parse()

	if inPath == "" || outPath == "" {
		exitf("-input and -output are required")
	}
	if minLen < 1 {
		exitf("-minlen must be >= 1")
	}

	f, err := os.Open(inPath)
	if err != nil {
		exitErr(err)
	}
	defer f.Close()

	data, st, err := buildFromReader(f, strict, minLen)
	if err != nil {
		exitErr(err)
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		exitErr(err)
	}

	st.OutputBytes = len(data)
	if !quiet {
		fmt.Fprintf(os.Stderr,
			"buildwordsac: lines=%d accepted=%d deduped=%d skipped_empty=%d skipped_short=%d skipped_bad=%d states=%d next=%d out_bytes=%d\n",
			st.Lines, st.Accepted, st.Deduped, st.SkippedEmpty, st.SkippedShort, st.SkippedBad,
			st.StateCount, st.NextCount, st.OutputBytes)
	}
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "buildwordsac: "+format+"\n", args...)
	os.Exit(2)
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "buildwordsac: %v\n", err)
	os.Exit(1)
}

func buildFromReader(f *os.File, strict bool, minLen int) ([]byte, stats, error) {
	var st stats

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	words := make([]string, 0, 1<<20)
	for scanner.Scan() {
		st.Lines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			st.SkippedEmpty++
			continue
		}

		norm, ok := normalizeASCII(line)
		if !ok {
			st.SkippedBad++
			if strict {
				return nil, st, fmt.Errorf("strict mode: non [A-Za-z] token: %q", line)
			}
			continue
		}
		if len(norm) < minLen {
			st.SkippedShort++
			continue
		}
		if len(norm) > st.MaxWordLen {
			st.MaxWordLen = len(norm)
		}
		words = append(words, norm)
	}
	if err := scanner.Err(); err != nil {
		return nil, st, err
	}
	if len(words) == 0 {
		return nil, st, errors.New("no usable words")
	}

	sort.Strings(words)
	words, st.Deduped = dedupeSorted(words)
	st.Accepted = len(words)

	nodes := make([]node, 1, 1<<20)
	for _, w := range words {
		insert(&nodes, w)
	}

	buildFailureLinks(nodes)

	st.StateCount = len(nodes)
	st.NextCount = countEdges(nodes)

	data, err := serialize(nodes, uint16(st.MaxWordLen), uint32(st.NextCount))
	if err != nil {
		return nil, st, err
	}
	return data, st, nil
}

func normalizeASCII(s string) (string, bool) {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c < 'a' || c > 'z' {
			return "", false
		}
		b = append(b, c)
	}
	return string(b), true
}

func dedupeSorted(in []string) ([]string, int) {
	if len(in) == 0 {
		return in, 0
	}
	w := 1
	for i := 1; i < len(in); i++ {
		if in[i] == in[i-1] {
			continue
		}
		in[w] = in[i]
		w++
	}
	return in[:w], len(in) - w
}

func insert(nodes *[]node, word string) {
	cur := uint32(0)
	for i := 0; i < len(word); i++ {
		idx := word[i] - 'a'
		n := &(*nodes)[cur]
		child := n.next[idx]
		if child == 0 {
			*nodes = append(*nodes, node{})
			newID := uint32(len(*nodes) - 1)
			n.next[idx] = newID + 1
			child = newID + 1
		}
		cur = child - 1
	}
	end := &(*nodes)[cur]
	l := uint16(len(word))
	if l > end.termMax {
		end.termMax = l
	}
}

func buildFailureLinks(nodes []node) {
	queue := make([]uint32, 0, len(nodes))

	nodes[0].outMax = nodes[0].termMax

	for c := 0; c < alphabetSize; c++ {
		child := nodes[0].next[c]
		if child == 0 {
			continue
		}
		s := child - 1
		nodes[s].fail = 0
		nodes[s].outMax = maxU16(nodes[s].termMax, nodes[0].outMax)
		queue = append(queue, s)
	}

	for head := 0; head < len(queue); head++ {
		r := queue[head]
		for c := 0; c < alphabetSize; c++ {
			child := nodes[r].next[c]
			if child == 0 {
				continue
			}
			s := child - 1

			f := nodes[r].fail
			for f != 0 && nodes[f].next[c] == 0 {
				f = nodes[f].fail
			}
			if nodes[f].next[c] != 0 {
				nodes[s].fail = nodes[f].next[c] - 1
			} else {
				nodes[s].fail = 0
			}

			nodes[s].outMax = maxU16(nodes[s].termMax, nodes[nodes[s].fail].outMax)
			queue = append(queue, s)
		}
	}
}

func countEdges(nodes []node) int {
	cnt := 0
	for i := range nodes {
		for c := 0; c < alphabetSize; c++ {
			if nodes[i].next[c] != 0 {
				cnt++
			}
		}
	}
	return cnt
}

func serialize(nodes []node, maxWordLen uint16, nextCount uint32) ([]byte, error) {
	stateCount := uint32(len(nodes))
	statesOff := uint32(headerSize)
	nextOff := statesOff + stateCount*stateRecSize
	totalLen64 := int64(nextOff) + int64(nextCount)*4
	if totalLen64 > int64(^uint(0)>>1) {
		return nil, errors.New("output too large")
	}
	totalLen := int(totalLen64)

	buf := make([]byte, totalLen)

	copy(buf[0:4], []byte(fileMagic))
	binary.LittleEndian.PutUint16(buf[4:], uint16(fileVersion))
	binary.LittleEndian.PutUint16(buf[6:], uint16(alphabetSize))
	binary.LittleEndian.PutUint32(buf[8:], stateCount)
	binary.LittleEndian.PutUint32(buf[12:], nextCount)
	binary.LittleEndian.PutUint16(buf[16:], maxWordLen)
	binary.LittleEndian.PutUint16(buf[18:], 0)
	binary.LittleEndian.PutUint32(buf[20:], statesOff)
	binary.LittleEndian.PutUint32(buf[24:], nextOff)

	nextWrite := uint32(0)

	for s := uint32(0); s < stateCount; s++ {
		n := nodes[s]
		var mask uint32
		for c := 0; c < alphabetSize; c++ {
			if n.next[c] != 0 {
				mask |= 1 << uint32(c)
			}
		}
		base := nextWrite

		off := int(statesOff + s*stateRecSize)
		binary.LittleEndian.PutUint32(buf[off+0:], mask)
		binary.LittleEndian.PutUint32(buf[off+4:], base)
		binary.LittleEndian.PutUint32(buf[off+8:], n.fail)
		binary.LittleEndian.PutUint16(buf[off+12:], n.outMax)
		binary.LittleEndian.PutUint16(buf[off+14:], 0)

		writePos := int(nextOff) + int(base)*4
		for c := 0; c < alphabetSize; c++ {
			child := n.next[c]
			if child == 0 {
				continue
			}
			binary.LittleEndian.PutUint32(buf[writePos:], child-1)
			writePos += 4
			nextWrite++
		}
	}

	if nextWrite != nextCount {
		return nil, fmt.Errorf("internal error: nextWrite=%d nextCount=%d", nextWrite, nextCount)
	}

	crc := crc32.ChecksumIEEE(buf[statesOff:])
	binary.LittleEndian.PutUint32(buf[28:], crc)

	return buf, nil
}

func maxU16(a, b uint16) uint16 {
	if a > b {
		return a
	}
	return b
}
