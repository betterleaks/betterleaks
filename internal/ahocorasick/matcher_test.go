package ahocorasick

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

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
}

func TestVisitPrefixPairsAndFoldedOffsets(t *testing.T) {
	long := strings.Repeat("a", 150)
	raw := "\xffxſKey!xSKey!Keſk!K" + long + "ſ!\xc5\xe2key"
	for _, patterns := range [][]string{
		{"xskey", "skey", "key", "kesk", long, "k" + long + "s", "key"},
		{"xskey", "sk", "k"}, // short keywords disable pair skipping
	} {
		for _, folded := range []bool{false, true} {
			m := Compile(patterns, folded)
			var expected [][3]int
			for id, p := range patterns {
				pattern := "^" + regexp.QuoteMeta(p)
				if folded {
					pattern = "(?i)" + pattern
				}
				re := regexp.MustCompile(pattern)
				for start := range len(raw) {
					if idx := re.FindStringIndex(raw[start:]); idx != nil {
						expected = append(expected, [3]int{id, start, start + idx[1]})
					}
				}
			}
			// The DFA emits each terminal before inherited suffixes and keeps
			// registration order for duplicates.
			slices.SortStableFunc(expected, func(a, b [3]int) int {
				if a[2] != b[2] {
					return a[2] - b[2]
				}
				return a[1] - b[1]
			})
			for offset := range 24 {
				prefix := strings.Repeat("!", 32+offset)
				for _, limit := range []int{1, len(expected)} {
					var got [][3]int
					m.Visit(prefix+raw, func(id, start, end int) bool {
						got = append(got, [3]int{id, start - len(prefix), end - len(prefix)})
						return len(got) < limit
					})
					require.Equal(t, expected[:limit], got, "folded=%t offset=%d limit=%d", folded, offset, limit)
				}
			}
		}
	}
}

func TestVisitAcrossProbeIntervals(t *testing.T) {
	m := Compile([]string{"needle"}, true)
	for offset := range 8 {
		// Start in dense prefixes, then cross into sparse data and back.
		dense := strings.Repeat("ne", 2048)
		first := dense[:len(dense)-offset]
		second := first + "needle" + strings.Repeat("!", 4096)
		raw := second + "NEEDLE" + dense
		var got [][2]int
		m.Visit(raw, func(_, start, end int) bool {
			got = append(got, [2]int{start, end})
			return true
		})
		require.Equal(t, [][2]int{{len(first), len(first) + 6}, {len(second), len(second) + 6}}, got)
	}
}
