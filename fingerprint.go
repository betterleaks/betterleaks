package betterleaks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zeebo/xxh3"
)

// AddFingerprintToFinding computes and sets the fingerprint on a finding.
//
// A fingerprint is a deterministic, unique identifier for a finding. It encodes
// where the finding was found, which rule matched, and a hash of the secret
// value. Two scans of the same content will always produce the same fingerprint,
// making fingerprints suitable for deduplication, ignore lists, and baselines.
//
// # Format
//
// The fingerprint uses "!" to delimit identity segments and "#" to anchor
// location information (analogous to URL fragments):
//
//	{source}!{resource_kind}!{identity_kvs}!{rule_id}!{secret_hash}#L{startLine}-{endLine}#C{startCol}-{endCol}
//
// Each segment:
//
//   - source:        The source type ("git", "file", "github", "s3", ...)
//   - resource_kind: The kind of resource ("git_patch_content", "file_content", ...)
//   - identity_kvs:  Sorted key=value pairs that identify the resource within its source.
//     Which keys are used depends on the resource kind (see [ResourceKind.FingerprintKeys]):
//     git patches use "commit_sha,path"; files use "path"; etc.
//   - rule_id:       The ID of the rule that matched
//   - secret_hash:   First 8 hex chars of the XXH3 hash of the secret value
//   - #L, #C:        Line and column ranges within the resource
//
// # Composite rules
//
// When a rule has required rules (composite detection), the required findings
// are appended as additional segments, sorted by rule ID (then by secret hash
// as tiebreaker) for deterministic ordering:
//
//	{primary_fingerprint}!{req_rule_id}!{req_secret_hash}#L...#C...[ !{req_rule_id}!... ]
//
// # Examples
//
// A private key found in a git patch:
//
//	git!git_patch_content!commit_sha=abc123,path=src/auth.py!private-key!a1b2c3d4#L10-12#C1-40
//
// An AWS access key found in a local file:
//
//	file!file_content!path=credentials.env!aws-access-key!e5f6a7b8#L3-3#C20-40
//
// A composite AWS key pair (access key ID + secret access key found together):
//
//	file!file_content!path=creds.env!aws-key-pair!e5f6a7b8#L3-3#C20-40!aws-secret-key!c9d0e1f2#L4-4#C25-65
//
// A GitHub comment containing an API token:
//
//	github!github_comment!comment_id=123456,repo=org/repo!api-token!b3c4d5e6#L1-1#C15-55
func AddFingerprintToFinding(finding *Finding) {
	r := finding.Fragment.Resource

	var b strings.Builder
	fmt.Fprintf(&b, "%s!%s!%s!%s!%s#L%d-%d#C%d-%d",
		r.Source,
		r.Kind,
		r.FingerprintIdentity(),
		finding.RuleID,
		secretHash(finding.Secret),
		finding.StartLine, finding.EndLine,
		finding.StartColumn, finding.EndColumn,
	)

	// Append required findings for composite rules, sorted for determinism.
	if len(finding.requiredFindings) > 0 {
		sorted := make([]*Finding, len(finding.requiredFindings))
		copy(sorted, finding.requiredFindings)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].RuleID != sorted[j].RuleID {
				return sorted[i].RuleID < sorted[j].RuleID
			}
			return secretHash(sorted[i].Secret) < secretHash(sorted[j].Secret)
		})

		for _, rf := range sorted {
			fmt.Fprintf(&b, "!%s!%s#L%d-%d#C%d-%d",
				rf.RuleID,
				secretHash(rf.Secret),
				rf.StartLine, rf.EndLine,
				rf.StartColumn, rf.EndColumn,
			)
		}
	}

	finding.Fingerprint = b.String()
}

// secretHash returns the first 8 hex characters of the XXH3-64 hash of s.
// XXH3 is used over SHA-256 because this is not a security context —
// it's ~20x faster and 8 hex chars (32 bits) is sufficient for per-resource dedup.
func secretHash(s string) string {
	h := xxh3.HashString(s)
	return fmt.Sprintf("%016x", h)[:8]
}
