package betterleaks

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Register test kinds. The real registrations live in sources/file/ and sources/git/
// via init(), but we can't import them here (import cycle). These use the same
// string values so fingerprint tests exercise real behavior.
func init() {
	RegisterResourceKind(ResourceKindInfo{
		Kind:         "file_content",
		IdentityKeys: []string{MetaPath},
		Source:       "file",
	})
	RegisterResourceKind(ResourceKindInfo{
		Kind:         "git_patch_content",
		IdentityKeys: []string{MetaCommitSHA, MetaPath},
		Source:       "git",
	})
	RegisterResourceKind(ResourceKindInfo{
		Kind:         "git_commit_message",
		IdentityKeys: []string{MetaCommitSHA, MetaPath},
		Source:       "git",
	})
	RegisterResourceKind(ResourceKindInfo{
		Kind:         "git_commit_body",
		IdentityKeys: []string{MetaCommitSHA, MetaPath},
		Source:       "git",
	})
}

func TestFingerprintKeys_AllResourceKinds(t *testing.T) {
	// Test all defined ResourceKind constants
	kinds := []ResourceKind{
		"file_content",
		"git_commit_message",
		"git_commit_body",
		"git_patch_content",
	}

	for _, kind := range kinds {
		keys := kind.FingerprintKeys()
		assert.NotEmpty(t, keys, "FingerprintKeys() should return non-empty slice for %s", kind)

		// Assert keys are in alphabetical order
		sorted := make([]string, len(keys))
		copy(sorted, keys)
		sort.Strings(sorted)
		assert.Equal(t, sorted, keys, "FingerprintKeys() should return keys in alphabetical order for %s", kind)
	}
}

func TestFingerprintIdentity_GitPatch(t *testing.T) {
	r := &Resource{
		Kind:   "git_patch_content",
		Source: "git",
		Metadata: map[string]string{
			MetaCommitSHA: "abc123",
			MetaPath:      "src/auth.py",
		},
	}

	identity := r.FingerprintIdentity()
	assert.Equal(t, "commit_sha=abc123,path=src/auth.py", identity)
}

func TestFingerprintIdentity_File(t *testing.T) {
	r := &Resource{
		Kind:   "file_content",
		Source: "file",
		Metadata: map[string]string{
			MetaPath: "config/secrets.yaml",
		},
	}

	identity := r.FingerprintIdentity()
	assert.Equal(t, "path=config/secrets.yaml", identity)
}

func TestFingerprintIdentity_Cached(t *testing.T) {
	r := &Resource{
		Kind:   "file_content",
		Source: "file",
		Metadata: map[string]string{
			MetaPath: "test.txt",
		},
	}

	// First call
	identity1 := r.FingerprintIdentity()
	assert.NotEmpty(t, r.fingerprintIdentity, "fingerprintIdentity should be cached after first call")

	// Second call should return same result
	identity2 := r.FingerprintIdentity()
	assert.Equal(t, identity1, identity2)
}

func TestAddFingerprintToFinding_Git(t *testing.T) {
	r := &Resource{
		Kind:   "git_patch_content",
		Source: "git",
		Metadata: map[string]string{
			MetaCommitSHA: "abc123",
			MetaPath:      "src/auth.py",
		},
	}

	finding := &Finding{
		RuleID:      "aws-access-key",
		Secret:      "AKIAIOSFODNN7EXAMPLE",
		StartLine:   42,
		EndLine:     42,
		StartColumn: 5,
		EndColumn:   25,
		Fragment:    &Fragment{Resource: r},
	}

	AddFingerprintToFinding(finding)

	// Format: {source}!{resource_kind}!{identity_kvs}!{rule_id}!{secret_hash}#L{start}-{end}#C{start}-{end}
	parts := strings.Split(finding.Fingerprint, "!")
	assert.Len(t, parts, 5)
	assert.Equal(t, "git", parts[0])
	assert.Equal(t, "git_patch_content", parts[1])
	assert.Equal(t, "commit_sha=abc123,path=src/auth.py", parts[2])
	assert.Equal(t, "aws-access-key", parts[3])

	// Last part: {secret_hash}#L{start}-{end}#C{start}-{end}
	hashAndLoc := strings.Split(parts[4], "#")
	assert.Len(t, hashAndLoc, 3)
	assert.Len(t, hashAndLoc[0], 8, "secret hash should be exactly 8 hex characters")
	assert.Equal(t, "L42-42", hashAndLoc[1])
	assert.Equal(t, "C5-25", hashAndLoc[2])
}

func TestAddFingerprintToFinding_File(t *testing.T) {
	r := &Resource{
		Kind:   "file_content",
		Source: "file",
		Metadata: map[string]string{
			MetaPath: "config/secrets.yaml",
		},
	}

	finding := &Finding{
		RuleID:      "private-key",
		Secret:      "-----BEGIN RSA PRIVATE KEY-----",
		StartLine:   10,
		EndLine:     12,
		StartColumn: 1,
		EndColumn:   40,
		Fragment:    &Fragment{Resource: r},
	}

	AddFingerprintToFinding(finding)

	parts := strings.Split(finding.Fingerprint, "!")
	assert.Len(t, parts, 5)
	assert.Equal(t, "file", parts[0])
	assert.Equal(t, "file_content", parts[1])
	assert.Equal(t, "path=config/secrets.yaml", parts[2])
	assert.Equal(t, "private-key", parts[3])

	hashAndLoc := strings.Split(parts[4], "#")
	assert.Len(t, hashAndLoc, 3)
	assert.Len(t, hashAndLoc[0], 8, "secret hash should be exactly 8 hex characters")
	assert.Equal(t, "L10-12", hashAndLoc[1])
	assert.Equal(t, "C1-40", hashAndLoc[2])
}

func TestAddFingerprintToFinding_Composite(t *testing.T) {
	r := &Resource{
		Kind:   "file_content",
		Source: "file",
		Metadata: map[string]string{
			MetaPath: "credentials.env",
		},
	}

	finding := &Finding{
		RuleID:      "aws-key-pair",
		Secret:      "AKIAIOSFODNN7EXAMPLE",
		StartLine:   10,
		EndLine:     10,
		StartColumn: 20,
		EndColumn:   40,
		Fragment:    &Fragment{Resource: r},
	}
	finding.AddRequiredFindings([]*Finding{
		{
			RuleID:      "aws-secret-access-key",
			Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			StartLine:   11,
			EndLine:     11,
			StartColumn: 25,
			EndColumn:   65,
		},
	})

	AddFingerprintToFinding(finding)

	// Primary + 1 required: 5 base parts + 2 parts per required finding
	parts := strings.Split(finding.Fingerprint, "!")
	assert.Len(t, parts, 7, "composite fingerprint: 5 base + 2 per required finding")
	assert.Equal(t, "file", parts[0])
	assert.Equal(t, "file_content", parts[1])
	assert.Equal(t, "path=credentials.env", parts[2])
	assert.Equal(t, "aws-key-pair", parts[3])

	// Primary location
	primaryHashLoc := strings.Split(parts[4], "#")
	assert.Len(t, primaryHashLoc, 3)
	assert.Len(t, primaryHashLoc[0], 8)
	assert.Equal(t, "L10-10", primaryHashLoc[1])
	assert.Equal(t, "C20-40", primaryHashLoc[2])

	// Required finding
	assert.Equal(t, "aws-secret-access-key", parts[5])
	reqHashLoc := strings.Split(parts[6], "#")
	assert.Len(t, reqHashLoc, 3)
	assert.Len(t, reqHashLoc[0], 8)
	assert.Equal(t, "L11-11", reqHashLoc[1])
	assert.Equal(t, "C25-65", reqHashLoc[2])
}

func TestAddFingerprintToFinding_CompositeMultipleRequired_Sorted(t *testing.T) {
	r := &Resource{
		Kind:   "file_content",
		Source: "file",
		Metadata: map[string]string{
			MetaPath: "creds.yaml",
		},
	}

	finding := &Finding{
		RuleID:      "cloud-credentials",
		Secret:      "primary-secret",
		StartLine:   5,
		EndLine:     5,
		StartColumn: 1,
		EndColumn:   20,
		Fragment:    &Fragment{Resource: r},
	}

	// Add required findings in non-alphabetical order
	finding.AddRequiredFindings([]*Finding{
		{
			RuleID:      "z-token",
			Secret:      "z-secret-value",
			StartLine:   7,
			EndLine:     7,
			StartColumn: 1,
			EndColumn:   20,
		},
		{
			RuleID:      "a-key-id",
			Secret:      "a-secret-value",
			StartLine:   6,
			EndLine:     6,
			StartColumn: 1,
			EndColumn:   20,
		},
	})

	AddFingerprintToFinding(finding)
	fp1 := finding.Fingerprint

	// Reverse the order of required findings and recompute
	finding.requiredFindings = []*Finding{
		finding.requiredFindings[1],
		finding.requiredFindings[0],
	}
	AddFingerprintToFinding(finding)
	fp2 := finding.Fingerprint

	assert.Equal(t, fp1, fp2, "fingerprint should be deterministic regardless of required finding order")

	// Verify a-key-id comes before z-token in the fingerprint
	parts := strings.Split(finding.Fingerprint, "!")
	assert.Len(t, parts, 9, "5 base + 2*2 required")
	assert.Equal(t, "a-key-id", parts[5])
	assert.Equal(t, "z-token", parts[7])
}

func TestAddFingerprintToFinding_CompositeVsNonComposite_Different(t *testing.T) {
	r := &Resource{
		Kind:   "file_content",
		Source: "file",
		Metadata: map[string]string{
			MetaPath: "test.env",
		},
	}

	// Non-composite finding
	nonComposite := &Finding{
		RuleID:      "my-rule",
		Secret:      "secret123",
		StartLine:   1,
		EndLine:     1,
		StartColumn: 1,
		EndColumn:   10,
		Fragment:    &Fragment{Resource: r},
	}
	AddFingerprintToFinding(nonComposite)

	// Same primary finding but with required findings attached
	composite := &Finding{
		RuleID:      "my-rule",
		Secret:      "secret123",
		StartLine:   1,
		EndLine:     1,
		StartColumn: 1,
		EndColumn:   10,
		Fragment:    &Fragment{Resource: r},
	}
	composite.AddRequiredFindings([]*Finding{
		{
			RuleID:      "aux-rule",
			Secret:      "aux-secret",
			StartLine:   2,
			EndLine:     2,
			StartColumn: 1,
			EndColumn:   15,
		},
	})
	AddFingerprintToFinding(composite)

	assert.NotEqual(t, nonComposite.Fingerprint, composite.Fingerprint,
		"composite fingerprint should differ from non-composite")

	// Non-composite fingerprint should be a prefix of composite
	assert.True(t, strings.HasPrefix(composite.Fingerprint, nonComposite.Fingerprint),
		"composite fingerprint should start with the primary fingerprint")
}

func TestSecretHash_Deterministic(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	hash1 := secretHash(secret)
	hash2 := secretHash(secret)
	assert.Equal(t, hash1, hash2, "same secret should produce same hash")
}

func TestSecretHash_DifferentSecrets(t *testing.T) {
	secrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"AKIAI44QH8DHBEXAMPLE",
		"my-super-secret-key-123",
		"password123",
	}

	hashes := make(map[string]bool)
	for _, s := range secrets {
		h := secretHash(s)
		assert.False(t, hashes[h], "different secrets should produce different hashes")
		hashes[h] = true
	}
}

func TestSecretHash_Length(t *testing.T) {
	secrets := []string{
		"short",
		"a much longer secret that spans many characters",
		"AKIAIOSFODNN7EXAMPLE",
		"",
	}

	for _, s := range secrets {
		h := secretHash(s)
		assert.Len(t, h, 8, "hash should always be exactly 8 hex characters")
	}
}
