package betterleaks

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFingerprintKeys_AllResourceKinds(t *testing.T) {
	// Test all defined ResourceKind constants
	kinds := []ResourceKind{
		FileContent,
		GitCommitMessage,
		GitCommitBody,
		GitPatchContent,
		GitHubComment,
		GitHubIssueDescription,
		GitHubIssueTitle,
		GitHubPullRequestTitle,
		GitHubPullRequestBody,
		S3Object,
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
		Kind:   GitPatchContent,
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
		Kind:   FileContent,
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
		Kind:   FileContent,
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
		Kind:   GitPatchContent,
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

	// Check format: {source}!{resource_kind}!{identity_kvs}!{rule_id}!{secret_hash}!L{start}-{end}!C{start}-{end}
	parts := strings.Split(finding.Fingerprint, "!")
	assert.Len(t, parts, 7)
	assert.Equal(t, "git", parts[0])
	assert.Equal(t, "git_patch_content", parts[1])
	assert.Equal(t, "commit_sha=abc123,path=src/auth.py", parts[2])
	assert.Equal(t, "aws-access-key", parts[3])
	assert.Len(t, parts[4], 8, "secret hash should be exactly 8 hex characters")
	assert.Equal(t, "L42-42", parts[5])
	assert.Equal(t, "C5-25", parts[6])
}

func TestAddFingerprintToFinding_File(t *testing.T) {
	r := &Resource{
		Kind:   FileContent,
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
	assert.Len(t, parts, 7)
	assert.Equal(t, "file", parts[0])
	assert.Equal(t, "file_content", parts[1])
	assert.Equal(t, "path=config/secrets.yaml", parts[2])
	assert.Equal(t, "private-key", parts[3])
	assert.Len(t, parts[4], 8, "secret hash should be exactly 8 hex characters")
	assert.Equal(t, "L10-12", parts[5])
	assert.Equal(t, "C1-40", parts[6])
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
