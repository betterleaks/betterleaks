package ahocorasick

import (
	"fmt"
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
