package celenv

import (
	"math"
	"testing"
)

func TestCelShannonEntropyCountsRunes(t *testing.T) {
	// Reference implementation: rune counts over byte length, matching
	// detect.shannonEntropy. A byte-based count would diverge for multi-byte
	// input, so this pins celShannonEntropy to the rune-based result.
	want := func(s string) float64 {
		if len(s) == 0 {
			return 0
		}
		counts := map[rune]int{}
		for _, r := range s {
			counts[r]++
		}
		inv := 1.0 / float64(len(s))
		var h float64
		for _, c := range counts {
			p := float64(c) * inv
			h -= p * math.Log2(p)
		}
		return h
	}

	for _, s := range []string{"", "a", "aabb", "abcd1234", "日本語テスト", "🔑🔑🔒"} {
		got := celShannonEntropy(s)
		if exp := want(s); math.Abs(got-exp) > 1e-9 {
			t.Errorf("celShannonEntropy(%q) = %v, want %v (rune-based)", s, got, exp)
		}
	}
}
