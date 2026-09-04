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

// List is an ordered, deduplicated collection of secret fingerprints.
type List struct{ hashes []Hash }

func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.hashes)
}

// FilterExpression returns the global finding filter represented by the list.
// Expr compiles a constant string list used with "in" into a map lookup.
func (l *List) FilterExpression() string {
	if l == nil || len(l.hashes) == 0 {
		return ""
	}
	var expression strings.Builder
	expression.WriteString("sha256(finding[\"secret\"]) in [\n")
	for _, hash := range l.hashes {
		_, _ = fmt.Fprintf(&expression, "  %q,\n", Format(hash))
	}
	expression.WriteByte(']')
	return expression.String()
}

type Diagnostic struct {
	Line   int
	Reason string
}

// Load parses an ignore file, retaining valid entries when other lines are bad.
func Load(r io.Reader) (*List, []Diagnostic, error) {
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
	return &List{hashes: hashes}, diagnostics, scanner.Err()
}
