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

const Prefix = "sha256:"

type Hash [sha256.Size]byte

func Sum(secret []byte) Hash { return sha256.Sum256(secret) }

func Format(hash Hash) string { return Prefix + hex.EncodeToString(hash[:]) }

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

// Set is immutable after construction and safe for concurrent reads.
type Set struct{ hashes map[Hash]struct{} }

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.hashes)
}

func (s *Set) Contains(secret string) bool {
	if s == nil || len(s.hashes) == 0 {
		return false
	}
	_, ok := s.hashes[Sum([]byte(secret))]
	return ok
}

type Diagnostic struct {
	Line   int
	Reason string
}

// Load parses an ignore file, retaining valid entries when other lines are bad.
func Load(r io.Reader) (*Set, []Diagnostic, error) {
	hashes := make(map[Hash]struct{})
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
		hashes[hash] = struct{}{}
	}
	return &Set{hashes: hashes}, diagnostics, scanner.Err()
}
