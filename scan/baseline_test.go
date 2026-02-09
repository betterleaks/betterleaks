package scan

import (
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/stretchr/testify/assert"
)

func TestIsNew_NewFormatFingerprints(t *testing.T) {
	// Both have new-format fingerprints
	finding := betterleaks.Finding{
		Fingerprint: "git!git_patch_content!commit_sha=abc,path=test.py!rule-id!hash1234#L10-10#C1-20",
		RuleID:      "rule-id",
	}

	baseline := []betterleaks.Finding{
		{
			Fingerprint: "git!git_patch_content!commit_sha=abc,path=test.py!rule-id!hash1234#L10-10#C1-20",
			RuleID:      "rule-id",
		},
	}

	// Matching fingerprints should return false (not new)
	assert.False(t, IsNew(finding, 0, baseline))

	// Different fingerprint should return true (is new)
	finding.Fingerprint = "git!git_patch_content!commit_sha=xyz,path=other.py!rule-id!hash1234#L10-10#C1-20"
	assert.True(t, IsNew(finding, 0, baseline))
}

func TestIsNew_MixedFormats(t *testing.T) {
	// Finding has new format, baseline has old format
	finding := betterleaks.Finding{
		Fingerprint: "git!git_patch_content!commit_sha=abc,path=test.py!rule-id!hash1234#L10-10#C1-20",
		RuleID:      "rule-id",
		StartLine:   10,
		EndLine:     10,
		StartColumn: 1,
		EndColumn:   20,
		Match:       "secret123",
		Secret:      "secret123",
		Metadata: map[string]string{
			betterleaks.MetaPath:          "test.py",
			betterleaks.MetaCommitSHA:     "abc",
			betterleaks.MetaAuthorName:    "author",
			betterleaks.MetaAuthorEmail:   "email",
			betterleaks.MetaCommitDate:    "date",
			betterleaks.MetaCommitMessage: "msg",
		},
	}

	baseline := []betterleaks.Finding{
		{
			Fingerprint: "abc:test.py:rule-id:10", // old format
			RuleID:      "rule-id",
			StartLine:   10,
			EndLine:     10,
			StartColumn: 1,
			EndColumn:   20,
			Match:       "secret123",
			Secret:      "secret123",
			Metadata: map[string]string{
				betterleaks.MetaPath:          "test.py",
				betterleaks.MetaCommitSHA:     "abc",
				betterleaks.MetaAuthorName:    "author",
				betterleaks.MetaAuthorEmail:   "email",
				betterleaks.MetaCommitDate:    "date",
				betterleaks.MetaCommitMessage: "msg",
			},
		},
	}

	// Should fall back to field-by-field comparison
	assert.False(t, IsNew(finding, 0, baseline))

	// Different field should make it new
	finding.StartLine = 11
	assert.True(t, IsNew(finding, 0, baseline))
}

func TestIsNew_BothOldFormat(t *testing.T) {
	finding := betterleaks.Finding{
		Fingerprint: "abc:test.py:rule-id:10", // old format
		RuleID:      "rule-id",
		StartLine:   10,
		EndLine:     10,
		StartColumn: 1,
		EndColumn:   20,
		Match:       "secret123",
		Secret:      "secret123",
		Metadata: map[string]string{
			betterleaks.MetaPath:          "test.py",
			betterleaks.MetaCommitSHA:     "abc",
			betterleaks.MetaAuthorName:    "author",
			betterleaks.MetaAuthorEmail:   "email",
			betterleaks.MetaCommitDate:    "date",
			betterleaks.MetaCommitMessage: "msg",
		},
	}

	baseline := []betterleaks.Finding{
		{
			Fingerprint: "abc:test.py:rule-id:10", // old format
			RuleID:      "rule-id",
			StartLine:   10,
			EndLine:     10,
			StartColumn: 1,
			EndColumn:   20,
			Match:       "secret123",
			Secret:      "secret123",
			Metadata: map[string]string{
				betterleaks.MetaPath:          "test.py",
				betterleaks.MetaCommitSHA:     "abc",
				betterleaks.MetaAuthorName:    "author",
				betterleaks.MetaAuthorEmail:   "email",
				betterleaks.MetaCommitDate:    "date",
				betterleaks.MetaCommitMessage: "msg",
			},
		},
	}

	// Should use field-by-field comparison for old format
	assert.False(t, IsNew(finding, 0, baseline))

	// Different secret should make it new
	finding.Secret = "different"
	assert.True(t, IsNew(finding, 0, baseline))
}

func TestIsNewFormatFingerprint(t *testing.T) {
	// New format (has !)
	assert.True(t, isNewFormatFingerprint("git!kind!identity!rule!hash!L1-1!C1-10"))

	// Old format (no !)
	assert.False(t, isNewFormatFingerprint("commit:path:rule:10"))
	assert.False(t, isNewFormatFingerprint("path:rule:10"))
}
