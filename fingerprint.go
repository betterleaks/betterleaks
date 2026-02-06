package betterleaks

import (
	"fmt"

	"github.com/zeebo/xxh3"
)

// AddFingerprintToFinding computes and sets the fingerprint on a finding.
func AddFingerprintToFinding(finding *Finding) {
	r := finding.Fragment.Resource
	finding.Fingerprint = fmt.Sprintf("%s!%s!%s!%s!%s!L%d-%d!C%d-%d",
		r.Source,
		r.Kind,
		r.FingerprintIdentity(),
		finding.RuleID,
		secretHash(finding.Secret),
		finding.StartLine, finding.EndLine,
		finding.StartColumn, finding.EndColumn,
	)
}

// secretHash returns the first 8 hex characters of the XXH3-64 hash of s.
// XXH3 is used over SHA-256 because this is not a security context —
// it's ~20x faster and 8 hex chars (32 bits) is sufficient for per-resource dedup.
func secretHash(s string) string {
	h := xxh3.HashString(s)
	return fmt.Sprintf("%016x", h)[:8]
}
