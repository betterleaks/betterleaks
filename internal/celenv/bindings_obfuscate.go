package celenv

import (
	"crypto/rand"
	"io"
	"math/big"
	"strings"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

const (
	obfuscateRate     = 0.7
	prefixMinLen      = 20
	prefixFallbackLen = 6
	prefixScanLen     = 8
	prefixSeparators  = "_-."
	classLower        = "abcdefghijklmnopqrstuvwxyz"
	classUpper        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	classDigit        = "0123456789"
	classHexLower     = "0123456789abcdef"
	classHexUpper     = "0123456789ABCDEF"
)

// obfuscateRand is the randomness source. Tests swap in a deterministic stream.
var obfuscateRand io.Reader = rand.Reader

func obfuscateBinding() functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		s, ok := val.(types.String)
		if !ok {
			return types.NewErr("obfuscate: secret must be a string, got %T", val)
		}
		return types.String(obfuscate(string(s)))
	}
}

// obfuscate returns a same-length, class-preserving perturbation of secret.
// Each rune is replaced with probability obfuscateRate by a different rune
// from the same class (lower, upper, digit, hex, or symbols present in
// secret). Non-ASCII runes pass through. For secrets longer than
// prefixMinLen, an identifying prefix is preserved verbatim — either up to
// the first separator within prefixScanLen, or prefixFallbackLen chars.
func obfuscate(secret string) string {
	if secret == "" {
		return ""
	}
	prefix, body := splitPrefix(secret)
	if body == "" {
		return secret
	}
	symbols := collectSymbols(body)
	hex := hexPool(body)
	runes := []rune(body)
	for i, r := range runes {
		if !shouldPerturb() {
			continue
		}
		runes[i] = perturbRune(r, symbols, hex)
	}
	return prefix + string(runes)
}

// splitPrefix returns the identifying prefix and the body to perturb.
// Short secrets have no preserved prefix.
func splitPrefix(secret string) (prefix, body string) {
	runes := []rune(secret)
	if len(runes) <= prefixMinLen {
		return "", secret
	}
	scan := prefixScanLen
	if scan > len(runes) {
		scan = len(runes)
	}
	for i := 0; i < scan; i++ {
		if strings.ContainsRune(prefixSeparators, runes[i]) {
			return string(runes[:i+1]), string(runes[i+1:])
		}
	}
	return string(runes[:prefixFallbackLen]), string(runes[prefixFallbackLen:])
}

// hexPool returns the hex alphabet to use for secret, or "" if secret isn't
// single-case hex. Mixed-case hex falls through to generic alphanumeric.
func hexPool(secret string) string {
	var hasLower, hasUpper bool
	for _, r := range secret {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
			hasLower = true
		case r >= 'A' && r <= 'F':
			hasUpper = true
		default:
			return ""
		}
	}
	switch {
	case hasLower && hasUpper:
		return ""
	case hasLower:
		return classHexLower
	case hasUpper:
		return classHexUpper
	default:
		return ""
	}
}

func collectSymbols(secret string) []rune {
	seen := make(map[rune]struct{})
	var out []rune
	for _, r := range secret {
		if !isSymbol(r) {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

func perturbRune(r rune, symbols []rune, hex string) rune {
	switch {
	case hex != "" && ((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')):
		return pickDifferent(hex, r)
	case r >= 'a' && r <= 'z':
		return pickDifferent(classLower, r)
	case r >= 'A' && r <= 'Z':
		return pickDifferent(classUpper, r)
	case r >= '0' && r <= '9':
		return pickDifferent(classDigit, r)
	case isSymbol(r):
		if len(symbols) <= 1 {
			return r
		}
		return pickDifferent(string(symbols), r)
	default:
		return r
	}
}

func isSymbol(r rune) bool {
	return r >= 0x21 && r <= 0x7e &&
		!(r >= 'a' && r <= 'z') &&
		!(r >= 'A' && r <= 'Z') &&
		!(r >= '0' && r <= '9')
}

func pickDifferent(pool string, current rune) rune {
	runes := []rune(pool)
	for {
		c := runes[randIndex(len(runes))]
		if c != current {
			return c
		}
	}
}

func shouldPerturb() bool {
	const denom = 1 << 53
	v, err := rand.Int(obfuscateRand, big.NewInt(denom))
	if err != nil {
		return true
	}
	return float64(v.Int64())/float64(denom) < obfuscateRate
}

func randIndex(n int) int {
	v, err := rand.Int(obfuscateRand, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
