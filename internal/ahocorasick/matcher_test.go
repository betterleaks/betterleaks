package ahocorasick

import (
	"fmt"
	"math/rand"
	"reflect"
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

// The two-chain walk must report exactly what the single chain reports, in
// the same order, across the midpoint and for matches longer than half the
// text.
func TestVisitTwoChainsMatchOneChain(t *testing.T) {
	patterns := []string{"key", "token", "secret", "api_key", "kelvin", "s", "longpatternabcdefghijklmnopqrstuvwxyz"}
	for _, fold := range []bool{true, false} {
		m := Compile(patterns, fold)
		rng := rand.New(rand.NewSource(11))
		alphabet := []byte("keytokensecretapi_KEYSToken \n=\"'xzq")
		for round := 0; round < 300; round++ {
			n := twoChainMinBytes + rng.Intn(3000)
			b := make([]byte, n)
			for i := range b {
				b[i] = alphabet[rng.Intn(len(alphabet))]
			}
			if round%7 == 0 {
				copy(b[n/2-3:], "longpatternabcdefghijklmnopqrstuvwxyz")
			}
			if round%11 == 0 {
				copy(b[n/2-1:], "secret")
			}
			text := string(b)
			type hit struct{ id, start, end int }
			var one, two []hit
			m.visitOne(text, func(id, start, end int) bool { one = append(one, hit{id, start, end}); return true })
			m.Visit(text, func(id, start, end int) bool { two = append(two, hit{id, start, end}); return true })
			if !reflect.DeepEqual(one, two) {
				t.Fatalf("fold=%v round %d: two-chain %d hits, one-chain %d hits; first divergence %v", fold, round, len(two), len(one), firstDiff(one, two))
			}
			// Early stop from fn is honored in both halves.
			stopAt := len(one) / 2
			var stopped []hit
			m.Visit(text, func(id, start, end int) bool {
				stopped = append(stopped, hit{id, start, end})
				return len(stopped) < stopAt
			})
			if stopAt > 0 && len(stopped) != stopAt {
				t.Fatalf("stop after %d hits reported %d", stopAt, len(stopped))
			}
		}
	}
}

func firstDiff[T comparable](a, b []T) any {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return []any{i, a[i], b[i]}
		}
	}
	return []any{"length", len(a), len(b)}
}
