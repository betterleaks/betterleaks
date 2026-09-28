// Package fingerprint hashes exact match values for reports and .betterleaksignore.
// Values may be secrets or non-secret components, such as account IDs.
// Fingerprints are SHA-256 digests formatted as 64 lowercase hexadecimal
// characters without a prefix.
package fingerprint

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Hash identifies exact match value bytes, independent of rule or location.
type Hash [sha256.Size]byte

// Sum hashes exact value bytes, including any whitespace.
func Sum(secret []byte) Hash { return sha256.Sum256(secret) }

// Format returns the SHA-256 digest as 64 lowercase hexadecimal characters.
func Format(hash Hash) string {
	return hex.EncodeToString(hash[:])
}

// Parse accepts exactly 64 hexadecimal characters in either case, without a prefix.
func Parse(s string) (Hash, error) {
	var hash Hash
	if len(s) != sha256.Size*2 {
		return hash, fmt.Errorf("SHA-256 digest must be exactly %d hexadecimal characters", sha256.Size*2)
	}
	if _, err := hex.Decode(hash[:], []byte(s)); err != nil {
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
