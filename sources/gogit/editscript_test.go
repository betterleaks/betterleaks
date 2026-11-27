package gogit

import (
	"context"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/require"
)

// The edit search must reproduce diffmatchpatch's scripts exactly, including
// empty runs, because shifted edits change which lines count as added.
func requireSameEdits(t *testing.T, s *editSearch, a, b []rune) {
	t.Helper()
	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = time.Hour
	var want []edit
	for _, d := range dmp.DiffMainRunes(a, b, false) {
		op := editEqual
		switch d.Type {
		case diffmatchpatch.DiffDelete:
			op = editDelete
		case diffmatchpatch.DiffInsert:
			op = editInsert
		}
		want = append(want, edit{op, utf8.RuneCountInString(d.Text)})
	}
	got, complete := s.diff(t.Context(), a, b, time.Hour)
	require.True(t, complete)
	require.Equal(t, want, got, "a=%v b=%v", a, b)
}

func TestHalfMatchHonorsSearchBudget(t *testing.T) {
	// Each occurrence of the seed in the repeated lines can extend to a
	// long match. Check cancellation and timeout inside this phase.
	long := []rune("x" + strings.Repeat("a", 16000) + "y")
	short := []rune("z" + strings.Repeat("a", 15000) + "w")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, s := range []editSearch{
		{ctx: ctx, deadline: time.Now().Add(time.Hour), stopped: false, v: nil},
		{ctx: t.Context(), deadline: time.Now().Add(-time.Second), stopped: false, v: nil},
	} {
		_, found := s.halfMatchAt(long, short, len(long)/4)
		require.False(t, found)
		require.True(t, s.stopped)
	}
}

func TestEditSearchMatchesDiffMatchPatch(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	token := func(alphabet int) rune {
		// Exercise multi-byte encodings as well as ASCII.
		return []rune{'a', 'b', 'c', 'é', '€', '😀', 0x10000 + 7, 0xe000}[rng.IntN(alphabet)]
	}
	var s editSearch
	for range 30000 {
		alphabet := 1 + rng.IntN(8)
		a := make([]rune, rng.IntN(60))
		for i := range a {
			a[i] = token(alphabet)
		}
		// Derive b from a with block edits, as successive file versions are.
		b := append([]rune(nil), a...)
		for range rng.IntN(6) {
			at := rng.IntN(len(b) + 1)
			switch rng.IntN(4) {
			case 0:
				b = append(b[:at], b[min(len(b), at+1+rng.IntN(8)):]...)
			case 1, 2:
				ins := make([]rune, 1+rng.IntN(8))
				for i := range ins {
					ins[i] = token(alphabet)
				}
				b = append(b[:at], append(ins, b[at:]...)...)
			case 3:
				if at < len(b) {
					block := append([]rune(nil), b[at:min(len(b), at+1+rng.IntN(10))]...)
					to := rng.IntN(len(b) + 1)
					b = append(b[:to], append(block, b[to:]...)...)
				}
			}
		}
		requireSameEdits(t, &s, a, b)
		requireSameEdits(t, &s, b, a)
	}
}

func TestEditSearchLargeHalfMatch(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	var s editSearch
	for range 200 {
		a := make([]rune, 200+rng.IntN(2000))
		for i := range a {
			a[i] = rune(1 + rng.IntN(50))
		}
		b := append([]rune(nil), a...)
		for range 1 + rng.IntN(40) {
			at := rng.IntN(len(b))
			b[at] = rune(1 + rng.IntN(60))
		}
		requireSameEdits(t, &s, a, b)
	}
}

// Compare the split itself, before the outer merge cleanup can hide a
// difference in which middle diagonal was chosen. Include partial words,
// duplicate tokens, no matches, both parities and unequal input lengths.
func TestWideSplitMatchesScalarBisect(t *testing.T) {
	rng := rand.New(rand.NewPCG(12, 91))
	var s editSearch
	s.ctx, s.deadline = t.Context(), time.Now().Add(time.Hour)
	for _, n := range []int{2, 19, 63, 64, 65, 127, 128, 129} {
		for _, m := range []int{2, 63, 64, 65, 129} {
			for _, alphabet := range []int{2, 7, 200} {
				a, b := make([]rune, n), make([]rune, m)
				for i := range a {
					a[i] = rune(rng.IntN(alphabet))
				}
				for i := range b {
					b[i] = rune(rng.IntN(alphabet))
				}
				a[0], a[n-1], b[0], b[m-1] = -1, -2, -3, -4
				want := s.bisect(a, b, -1)
				require.Equal(t, want, s.wideSplit(a, b, -1), "n=%d m=%d alphabet=%d", n, m, alphabet)
			}
		}
	}
}

func TestWideEditSearchMatchesDiffMatchPatch(t *testing.T) {
	rng := rand.New(rand.NewPCG(12, 92))
	var s editSearch
	for _, m := range []int{500, 1401, 2000} {
		a, b := make([]rune, 1400), make([]rune, m)
		for i := range a {
			a[i] = rune(rng.IntN(64))
		}
		for i := range b {
			b[i] = rune(rng.IntN(64))
		}
		requireSameEdits(t, &s, a, b)
		requireSameEdits(t, &s, b, a)
	}
}

func FuzzEditSearch(f *testing.F) {
	f.Add([]byte("abcabba"), []byte("cbabac"))
	f.Add([]byte("xaxcxabc"), []byte("abcy"))
	f.Fuzz(func(t *testing.T, x, y []byte) {
		if len(x)+len(y) > 512 {
			t.Skip()
		}
		toRunes := func(b []byte) []rune {
			r := make([]rune, len(b))
			for i, c := range b {
				r[i] = rune(c%8) + 'a'
			}
			return r
		}
		var s editSearch
		a, b := toRunes(x), toRunes(y)
		requireSameEdits(t, &s, a, b)
		// Force the wide path on short inputs too. The scalar search is an
		// independent oracle below its switching threshold.
		if len(a) >= 2 && len(b) >= 2 && len(a)+len(b) < 256 && a[0] != b[0] && a[len(a)-1] != b[len(b)-1] {
			s.ctx, s.deadline = t.Context(), time.Now().Add(time.Hour)
			require.Equal(t, s.bisect(a, b, -1), s.wideSplit(a, b, -1))
		}
	})
}
