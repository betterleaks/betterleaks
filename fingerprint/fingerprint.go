// Package fingerprint hashes exact match values for reports and .betterleaksignore.
// Values may be secrets or non-secret components, such as account IDs.
// Fingerprints are SHA-256 digests formatted as 64 lowercase hexadecimal
// characters without a prefix. Keyed fingerprints use HMAC-SHA-256 and the
// hmac-sha256: prefix. Ordinary fingerprints are identifiers, not a guarantee
// of confidentiality: anyone can hash guesses and compare them.
package fingerprint

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Hash identifies exact match value bytes, independent of rule or location.
// The zero value is an all-zero SHA-256 digest. Hash is comparable and can be a map key.
type Hash struct {
	digest [sha256.Size]byte
	keyed  bool
}

// Sum hashes exact value bytes, including any whitespace, using SHA-256.
func Sum(value []byte) Hash { return Hash{digest: sha256.Sum256(value)} }

// SumWithKey hashes exact value bytes using HMAC-SHA-256 when key is non-empty.
// An empty key selects ordinary SHA-256, equivalent to Sum.
// A stable, private key is required for keyed fingerprints to remain comparable.
func SumWithKey(value, key []byte) Hash {
	if len(key) == 0 {
		return Sum(value)
	}
	h := Hash{keyed: true}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	mac.Sum(h.digest[:0])
	return h
}

// IsHMAC reports whether the fingerprint requires an HMAC key.
func (h Hash) IsHMAC() bool { return h.keyed }

// Format returns lowercase hexadecimal, with hmac-sha256: for keyed fingerprints.
func Format(hash Hash) string {
	digest := hex.EncodeToString(hash.digest[:])
	if hash.keyed {
		return "hmac-sha256:" + digest
	}
	return digest
}

// Parse accepts 64 hexadecimal characters in either case, optionally preceded
// by the lowercase hmac-sha256: prefix. The sha256: prefix is not accepted.
func Parse(s string) (Hash, error) {
	var hash Hash
	if strings.HasPrefix(s, "hmac-sha256:") {
		hash.keyed = true
		s = strings.TrimPrefix(s, "hmac-sha256:")
	}
	if len(s) != sha256.Size*2 {
		return Hash{}, fmt.Errorf("SHA-256 digest must be exactly %d hexadecimal characters", sha256.Size*2)
	}
	if _, err := hex.Decode(hash.digest[:], []byte(s)); err != nil {
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
