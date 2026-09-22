// Package secrets produces repeatable synthetic credentials for rule fixtures.
package secrets

import (
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/lucasjones/reggen"
)

func NewSecret(regex string) string {
	g, err := reggen.NewGenerator(regex)
	if err != nil {
		panic(err)
	}
	// Each call starts the same sequence, independent of rule generation order.
	g.SetSeed(1)
	return g.Generate(1)
}

// NewSecretWithEntropy selects a repeatable fixture meeting the rule's minimum
// Shannon entropy threshold.
func NewSecretWithEntropy(regex string, minEntropy float64) string {
	g, err := reggen.NewGenerator(regex)
	if err != nil {
		panic(err)
	}
	g.SetSeed(1)
	for range 10 {
		s := g.Generate(1)
		if shannonEntropy(s) >= minEntropy {
			return s
		}
	}
	panic(fmt.Sprintf("no fixture with entropy >= %f after 10 attempts: %s", minEntropy, regex))
}

// shannonEntropy calculates the Shannon entropy of a string.
func shannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, c := range data {
		counts[c]++
	}
	invLen := 1.0 / float64(len(data))
	var entropy float64
	// Stable summation keeps threshold comparisons independent of map order.
	for _, c := range slices.Sorted(maps.Keys(counts)) {
		freq := float64(counts[c]) * invLen
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}
