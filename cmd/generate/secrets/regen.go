// Package reggen generates text based on regex definitions
// This is a slightly altered version of https://github.com/lucasjones/reggen
package secrets

import (
	"fmt"
	"math"

	"github.com/lucasjones/reggen"
)

func NewSecret(regex string) string {
	g, err := reggen.NewGenerator(regex)
	if err != nil {
		panic(err)
	}
	return g.Generate(1)
}

// NewSecretWithEntropy generates secrets from regex until one meets the minimum
// Shannon entropy threshold. This prevents flaky tests caused by low-entropy
// generated secrets being rejected by the entropy filter at scan time.
func NewSecretWithEntropy(regex string, minEntropy float64) string {
	g, err := reggen.NewGenerator(regex)
	if err != nil {
		panic(err)
	}
	for range 10 {
		s := g.Generate(1)
		if shannonEntropy(s) >= minEntropy {
			return s
		}
	}
	fmt.Printf("WARNING: failed to generate secret with entropy >= %f after 10 attempts: %s", minEntropy, regex)

	// returns empty string which will fail the validation tests and surface the rule failing
	return ""
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
	for _, n := range counts {
		freq := float64(n) * invLen
		entropy -= freq * math.Log2(freq)
	}
	return entropy
}
