package gogit

import (
	"math/rand/v2"
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
	require.Equal(t, want, s.diff(a, b, time.Hour), "a=%v b=%v", a, b)
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
		requireSameEdits(t, &s, toRunes(x), toRunes(y))
	})
}
