package ahocorasick

import (
	"fmt"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestVisit(t *testing.T) {
	m := Compile([]string{"he", "she", "hers", "his"}, true)
	var got [][3]int
	m.Visit("aHiS uSHers", func(id, start, end int) bool {
		got = append(got, [3]int{id, start, end})
		return true
	})
	require.Equal(t, [][3]int{{3, 1, 4}, {1, 6, 9}, {0, 7, 9}, {2, 7, 11}}, got)
}

func TestVisitUnicodeSimpleFoldOffsets(t *testing.T) {
	m := Compile([]string{"key", "secret"}, true)
	var got [][3]int
	m.Visit("KEY ſecret", func(id, start, end int) bool {
		got = append(got, [3]int{id, start, end})
		return true
	})
	require.Equal(t, [][3]int{{0, 0, len("KEY")}, {1, len("KEY "), len("KEY ſecret")}}, got)
}

func TestFoldRuneASCIIExhaustivelyMatchesUnicodeSimpleFold(t *testing.T) {
	reference := func(r rune) (byte, bool) {
		for next := r; ; next = unicode.SimpleFold(next) {
			if next < utf8.RuneSelf {
				return fold(byte(next), true), true
			}
			if folded := unicode.SimpleFold(next); folded == r {
				return 0, false
			}
		}
	}
	for r := rune(utf8.RuneSelf); r <= utf8.MaxRune; r++ {
		got, gotOK := FoldRuneASCII(r)
		want, wantOK := reference(r)
		if got != want || gotOK != wantOK {
			t.Fatalf("FoldRuneASCII(%U) = (%q, %v), want (%q, %v)", r, got, gotOK, want, wantOK)
		}
	}
}

func TestVisitBytesMatchesStringOffsets(t *testing.T) {
	m := Compile([]string{"key", "secret", "hers"}, true)
	text := "KEY uſecret hers"
	var fromString, fromBytes [][3]int
	m.Visit(text, func(id, start, end int) bool {
		fromString = append(fromString, [3]int{id, start, end})
		return true
	})
	m.VisitBytes([]byte(text), func(id, start, end int) bool {
		fromBytes = append(fromBytes, [3]int{id, start, end})
		return true
	})
	require.Equal(t, fromString, fromBytes)
}

func TestVisitIDsMatchesOffsetVisitors(t *testing.T) {
	m := Compile([]string{"key", "secret", "hers"}, true)
	text := "KEY uſecret hers"
	var withOffsets, fromString, fromBytes []int
	m.Visit(text, func(id, _, _ int) bool {
		withOffsets = append(withOffsets, id)
		return true
	})
	m.VisitIDs(text, func(id int) bool {
		fromString = append(fromString, id)
		return true
	})
	m.VisitIDsBytes([]byte(text), func(id int) bool {
		fromBytes = append(fromBytes, id)
		return true
	})
	require.Equal(t, withOffsets, fromString)
	require.Equal(t, withOffsets, fromBytes)
}

func TestVisitEndsMatchesOffsetVisitors(t *testing.T) {
	m := Compile([]string{"key", "secret", "hers"}, true)
	text := "KEY uſecret hers"
	var withOffsets, fromString, fromBytes [][2]int
	m.Visit(text, func(id, _, end int) bool {
		withOffsets = append(withOffsets, [2]int{id, end})
		return true
	})
	m.VisitEnds(text, func(id, end int) bool {
		fromString = append(fromString, [2]int{id, end})
		return true
	})
	m.VisitEndsBytes([]byte(text), func(id, end int) bool {
		fromBytes = append(fromBytes, [2]int{id, end})
		return true
	})
	require.Equal(t, withOffsets, fromString)
	require.Equal(t, withOffsets, fromBytes)
}

func TestVisitStableIDsAndStop(t *testing.T) {
	m := Compile([]string{"x", "x"}, false)
	var ids []int
	m.Visit("xx", func(id, _, _ int) bool {
		ids = append(ids, id)
		return len(ids) < 2
	})
	require.Equal(t, []int{0, 1}, ids)
}

func TestVisitConcurrent(t *testing.T) {
	m := Compile([]string{"needle"}, true)
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			for range 100 {
				matches := 0
				m.Visit("NEEDLE needle", func(_, _, _ int) bool { matches++; return true })
				require.Equal(t, 2, matches)
			}
		})
	}
}

func TestVisitASCIIAllocations(t *testing.T) {
	m := Compile([]string{"needle"}, true)
	allocs := testing.AllocsPerRun(100, func() {
		m.Visit("haystack NEEDLE haystack", func(_, _, _ int) bool { return true })
	})
	require.Zero(t, allocs)
	allocs = testing.AllocsPerRun(100, func() {
		m.VisitBytes([]byte("haystack NEEDLE haystack"), func(_, _, _ int) bool { return true })
	})
	require.Zero(t, allocs)
	allocs = testing.AllocsPerRun(100, func() {
		m.VisitIDsBytes([]byte("haystack NEEDLE haystack"), func(_ int) bool { return true })
	})
	require.Zero(t, allocs)
	allocs = testing.AllocsPerRun(100, func() {
		m.VisitEndsBytes([]byte("haystack NEEDLE haystack"), func(_, _ int) bool { return true })
	})
	require.Zero(t, allocs)
	allocs = testing.AllocsPerRun(100, func() {
		m.VisitEnds("haystack NEEDLE haystack", func(_, _ int) bool { return true })
	})
	require.Zero(t, allocs)
}
