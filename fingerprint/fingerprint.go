// Package fingerprint implements .betterleaksignore secret fingerprints.
package fingerprint

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Prefix identifies the supported SHA-256 fingerprint format.
const Prefix = "sha256:"

// Hash identifies the exact secret bytes, independent of rule or location.
type Hash [sha256.Size]byte

// Sum hashes exact secret bytes, including any whitespace.
func Sum(secret []byte) Hash { return sha256.Sum256(secret) }

// Format returns the canonical sha256: prefix and lowercase hexadecimal digest.
func Format(hash Hash) string { return Prefix + hex.EncodeToString(hash[:]) }

// Parse accepts a sha256: prefix followed by a full hexadecimal digest.
func Parse(s string) (Hash, error) {
	var hash Hash
	prefix, digest, ok := strings.Cut(s, ":")
	if !ok {
		return hash, fmt.Errorf("missing %q prefix", Prefix)
	}
	if prefix != "sha256" {
		return hash, fmt.Errorf("unsupported fingerprint algorithm %q", prefix)
	}
	if len(digest) != sha256.Size*2 {
		return hash, fmt.Errorf("SHA-256 digest must be exactly %d hexadecimal characters", sha256.Size*2)
	}
	if _, err := hex.Decode(hash[:], []byte(digest)); err != nil {
		return Hash{}, fmt.Errorf("invalid SHA-256 digest: %w", err)
	}
	return hash, nil
}

// Diagnostic describes an invalid entry in an ignore file. Line numbers start at one.
type Diagnostic struct {
	Line   int
	Reason string
}

// Load parses an ignore file, retaining valid entries when other lines are bad.
// Hashes are deduplicated in input order. On a read error, it returns the entries
// and diagnostics collected before that error.
func Load(r io.Reader) ([]Hash, []Diagnostic, error) {
	seen := make(map[Hash]struct{})
	var hashes []Hash
	var diagnostics []Diagnostic
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 1024*1024)
	for line := 1; scanner.Scan(); line++ {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		hash, err := Parse(entry)
		if err != nil {
			diagnostics = append(diagnostics, Diagnostic{Line: line, Reason: err.Error()})
			continue
		}
		if _, exists := seen[hash]; exists {
			continue
		}
		seen[hash] = struct{}{}
		hashes = append(hashes, hash)
	}
	return hashes, diagnostics, scanner.Err()
}
