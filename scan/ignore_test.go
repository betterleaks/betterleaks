package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Parsing tests

func TestParseIgnoreEntry_FullFingerprint(t *testing.T) {
	line := "git!git_patch_content!commit_sha=abc123,path=src/auth.py!aws-access-key!a1b2c3d4!L42-42!C5-25"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.True(t, isExact)
	assert.Equal(t, "git", m.Source)
	assert.Equal(t, "git_patch_content", m.ResourceKind)
	assert.Equal(t, map[string]string{"commit_sha": "abc123", "path": "src/auth.py"}, m.IdentityKVs)
	assert.Equal(t, "aws-access-key", m.RuleID)
	assert.Equal(t, "a1b2c3d4", m.SecretHash)
	assert.Equal(t, 42, m.StartLine)
	assert.Equal(t, 42, m.EndLine)
	assert.True(t, m.hasLines)
	assert.Equal(t, 5, m.StartColumn)
	assert.Equal(t, 25, m.EndColumn)
	assert.True(t, m.hasColumns)
}

func TestParseIgnoreEntry_WildcardSecretHash(t *testing.T) {
	line := "*!*!*!*!a1b2c3d4"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.False(t, isExact)
	assert.Empty(t, m.Source)
	assert.Empty(t, m.ResourceKind)
	assert.Nil(t, m.IdentityKVs)
	assert.Empty(t, m.RuleID)
	assert.Equal(t, "a1b2c3d4", m.SecretHash)
	assert.False(t, m.hasLines)
	assert.False(t, m.hasColumns)
}

func TestParseIgnoreEntry_WildcardRule(t *testing.T) {
	line := "*!*!*!aws-access-key"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.False(t, isExact)
	assert.Equal(t, "aws-access-key", m.RuleID)
	// Trailing segments are wildcards
	assert.Empty(t, m.SecretHash)
	assert.False(t, m.hasLines)
	assert.False(t, m.hasColumns)
}

func TestParseIgnoreEntry_PathOnly(t *testing.T) {
	line := "git!*!path=src/auth.py"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.False(t, isExact)
	assert.Equal(t, "git", m.Source)
	assert.Empty(t, m.ResourceKind) // * is wildcard
	assert.Equal(t, map[string]string{"path": "src/auth.py"}, m.IdentityKVs)
}

func TestParseIgnoreEntry_TrailingWildcardShorthand(t *testing.T) {
	// Only 3 segments - trailing ones should be wildcards
	line := "git!*!path=src/auth.py"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.False(t, isExact)
	assert.Equal(t, "git", m.Source)
	assert.Empty(t, m.ResourceKind)
	assert.Equal(t, map[string]string{"path": "src/auth.py"}, m.IdentityKVs)
	assert.Empty(t, m.RuleID)
	assert.Empty(t, m.SecretHash)
	assert.False(t, m.hasLines)
	assert.False(t, m.hasColumns)
}

func TestParseIgnoreEntry_Comments(t *testing.T) {
	lines := []string{
		"# This is a comment",
		"#comment without space",
	}

	for _, line := range lines {
		m, _ := ParseIgnoreEntry(line)
		assert.Nil(t, m, "comments should return nil")
	}
}

func TestParseIgnoreEntry_BlankLines(t *testing.T) {
	lines := []string{
		"",
		"   ",
		"\t",
	}

	for _, line := range lines {
		m, _ := ParseIgnoreEntry(line)
		assert.Nil(t, m, "blank lines should return nil")
	}
}

func TestParseIgnoreEntry_IdentityKVParsing(t *testing.T) {
	line := "git!*!commit_sha=abc,path=src/auth.py"
	m, _ := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.Equal(t, map[string]string{
		"commit_sha": "abc",
		"path":       "src/auth.py",
	}, m.IdentityKVs)
}

func TestParseIgnoreEntry_LineRange(t *testing.T) {
	line := "*!*!*!*!*!L42-42"
	m, _ := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.Equal(t, 42, m.StartLine)
	assert.Equal(t, 42, m.EndLine)
	assert.True(t, m.hasLines)
}

func TestParseIgnoreEntry_ColumnRange(t *testing.T) {
	line := "*!*!*!*!*!*!C5-25"
	m, _ := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.Equal(t, 5, m.StartColumn)
	assert.Equal(t, 25, m.EndColumn)
	assert.True(t, m.hasColumns)
}

// Legacy format tests

func TestParseLegacyEntry_3Part(t *testing.T) {
	line := "src/auth.py:aws-access-key:42"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.False(t, isExact)
	assert.Empty(t, m.Source)
	assert.Equal(t, map[string]string{"path": "src/auth.py"}, m.IdentityKVs)
	assert.Equal(t, "aws-access-key", m.RuleID)
	assert.Equal(t, 42, m.StartLine)
	assert.Equal(t, 42, m.EndLine)
	assert.True(t, m.hasLines)
}

func TestParseLegacyEntry_4Part(t *testing.T) {
	line := "abc123:src/auth.py:aws-access-key:42"
	m, isExact := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.False(t, isExact)
	assert.Equal(t, "git", m.Source)
	assert.Equal(t, map[string]string{
		"commit_sha": "abc123",
		"path":       "src/auth.py",
	}, m.IdentityKVs)
	assert.Equal(t, "aws-access-key", m.RuleID)
	assert.Equal(t, 42, m.StartLine)
	assert.Equal(t, 42, m.EndLine)
	assert.True(t, m.hasLines)
}

func TestParseLegacyEntry_BackslashNormalization(t *testing.T) {
	line := "src\\auth.py:rule:42"
	m, _ := ParseIgnoreEntry(line)

	require.NotNil(t, m)
	assert.Equal(t, map[string]string{"path": "src/auth.py"}, m.IdentityKVs)
}

func TestParseLegacyEntry_InvalidFormat(t *testing.T) {
	// 2-part and 5-part should return nil
	invalidLines := []string{
		"only:two",
		"one:two:three:four:five",
	}

	for _, line := range invalidLines {
		m, _ := ParseIgnoreEntry(line)
		assert.Nil(t, m, "invalid format %q should return nil", line)
	}
}

// Matching tests

func createTestFinding(source, kind, path, commit, ruleID, secretHash string, startLine, endLine, startCol, endCol int) *betterleaks.Finding {
	r := &betterleaks.Resource{
		Kind:   betterleaks.ResourceKind(kind),
		Source: source,
		Metadata: map[string]string{
			betterleaks.MetaPath:      path,
			betterleaks.MetaCommitSHA: commit,
		},
	}

	// Build fingerprint manually
	fingerprint := source + "!" + kind + "!"
	if commit != "" {
		fingerprint += "commit_sha=" + commit + ",path=" + path
	} else {
		fingerprint += "path=" + path
	}
	fingerprint += "!" + ruleID + "!" + secretHash
	fingerprint += "!L" + itoa(startLine) + "-" + itoa(endLine)
	fingerprint += "!C" + itoa(startCol) + "-" + itoa(endCol)

	return &betterleaks.Finding{
		RuleID:      ruleID,
		StartLine:   startLine,
		EndLine:     endLine,
		StartColumn: startCol,
		EndColumn:   endCol,
		Fragment:    &betterleaks.Fragment{Resource: r},
		Fingerprint: fingerprint,
	}
}

func itoa(i int) string {
	return string(rune('0')+rune(i/10)) + string(rune('0')+rune(i%10))
}

func TestIgnoreSet_ExactMatch(t *testing.T) {
	set := NewIgnoreSet()
	fingerprint := "git!git_patch_content!commit_sha=abc123,path=src/auth.py!aws-access-key!a1b2c3d4!L42-42!C05-25"
	set.Add(fingerprint)

	// Matching finding
	f := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "aws-access-key", "a1b2c3d4", 42, 42, 5, 25)
	f.Fingerprint = fingerprint
	assert.True(t, set.IsIgnored(f))

	// Non-matching finding
	f2 := createTestFinding("git", "git_patch_content", "src/other.py", "abc123", "aws-access-key", "a1b2c3d4", 42, 42, 5, 25)
	assert.False(t, set.IsIgnored(f2))
}

func TestIgnoreSet_WildcardSecretHash(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("*!*!*!*!a1b2c3d4")

	// Any finding with that secret hash should be ignored
	f1 := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "aws-access-key", "a1b2c3d4", 42, 42, 5, 25)
	assert.True(t, set.IsIgnored(f1))

	f2 := createTestFinding("file", "file_content", "other/path.py", "", "other-rule", "a1b2c3d4", 10, 10, 1, 20)
	assert.True(t, set.IsIgnored(f2))

	// Different secret hash should not match
	f3 := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "aws-access-key", "different", 42, 42, 5, 25)
	assert.False(t, set.IsIgnored(f3))
}

func TestIgnoreSet_WildcardRule(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("*!*!*!aws-access-key")

	// All findings with this rule ID should be ignored
	f1 := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "aws-access-key", "hash1234", 42, 42, 5, 25)
	assert.True(t, set.IsIgnored(f1))

	f2 := createTestFinding("file", "file_content", "other.py", "", "aws-access-key", "hash5678", 10, 10, 1, 20)
	assert.True(t, set.IsIgnored(f2))

	// Different rule should not match
	f3 := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "other-rule", "hash1234", 42, 42, 5, 25)
	assert.False(t, set.IsIgnored(f3))
}

func TestIgnoreSet_PathSubsetMatch(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("git!*!path=src/auth.py")

	// Git finding with matching path (subset match)
	f := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "any-rule", "anyhash1", 42, 42, 5, 25)
	assert.True(t, set.IsIgnored(f))
}

func TestIgnoreSet_PathSubsetNoMatch(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("git!*!path=src/auth.py")

	// Different path should not match
	f := createTestFinding("git", "git_patch_content", "src/other.py", "abc123", "any-rule", "anyhash1", 42, 42, 5, 25)
	assert.False(t, set.IsIgnored(f))
}

func TestIgnoreSet_LegacyGlobal(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("src/auth.py:aws-access-key:42")

	// Git finding at that path/rule/line
	f1 := createTestFinding("git", "git_patch_content", "src/auth.py", "xyz", "aws-access-key", "anyhash1", 42, 42, 5, 25)
	assert.True(t, set.IsIgnored(f1))

	// File finding with same path/rule/line
	f2 := createTestFinding("file", "file_content", "src/auth.py", "", "aws-access-key", "anyhash2", 42, 42, 1, 20)
	assert.True(t, set.IsIgnored(f2))

	// Different line should not match
	f3 := createTestFinding("git", "git_patch_content", "src/auth.py", "xyz", "aws-access-key", "anyhash1", 43, 43, 5, 25)
	assert.False(t, set.IsIgnored(f3))
}

func TestIgnoreSet_LegacyCommitSpecific(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("abc123:src/auth.py:aws-access-key:42")

	// Matching commit+path+rule+line
	f := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "aws-access-key", "anyhash1", 42, 42, 5, 25)
	assert.True(t, set.IsIgnored(f))

	// Different commit should not match
	f2 := createTestFinding("git", "git_patch_content", "src/auth.py", "different", "aws-access-key", "anyhash1", 42, 42, 5, 25)
	assert.False(t, set.IsIgnored(f2))
}

func TestIgnoreSet_NoMatchersShortCircuit(t *testing.T) {
	set := NewIgnoreSet()
	// Add only exact fingerprints (no wildcards)
	set.exact["exact-fingerprint-1"] = struct{}{}
	set.exact["exact-fingerprint-2"] = struct{}{}

	// Non-matching finding should return quickly
	f := createTestFinding("git", "git_patch_content", "src/auth.py", "abc123", "rule", "hash1234", 42, 42, 5, 25)
	assert.False(t, set.IsIgnored(f))

	// Verify matchers and unindexed are empty
	assert.Empty(t, set.matchers)
	assert.Empty(t, set.unindexed)
}

func TestIgnoreSet_GlobalSecretIgnore(t *testing.T) {
	set := NewIgnoreSet()
	set.Add("*!*!*!*!secretha")

	// Should match across multiple sources
	f1 := createTestFinding("git", "git_patch_content", "path1.py", "commit1", "rule1", "secretha", 1, 1, 1, 10)
	assert.True(t, set.IsIgnored(f1))

	f2 := createTestFinding("file", "file_content", "path2.py", "", "rule2", "secretha", 5, 5, 2, 20)
	assert.True(t, set.IsIgnored(f2))

	f3 := createTestFinding("git", "git_patch_content", "path3.py", "commit2", "rule3", "secretha", 10, 10, 3, 30)
	assert.True(t, set.IsIgnored(f3))
}

func TestIgnoreSet_MultipleMatchers(t *testing.T) {
	set := NewIgnoreSet()

	// Mix of exact, wildcard by hash, wildcard by rule, legacy
	exactFp := "git!git_patch_content!commit_sha=exact,path=exact.py!rule!hash1234!L01-01!C01-10"
	set.Add(exactFp)
	set.Add("*!*!*!*!wildcardh")
	set.Add("*!*!*!wildcard-rule")
	set.Add("legacy/path.py:legacy-rule:99")

	// Exact match
	f1 := &betterleaks.Finding{Fingerprint: exactFp}
	f1.Fragment = &betterleaks.Fragment{Resource: &betterleaks.Resource{Metadata: map[string]string{}}}
	assert.True(t, set.IsIgnored(f1))

	// Wildcard by hash
	f2 := createTestFinding("file", "file_content", "any.py", "", "any-rule", "wildcardh", 1, 1, 1, 1)
	assert.True(t, set.IsIgnored(f2))

	// Wildcard by rule
	f3 := createTestFinding("git", "git_patch_content", "any.py", "any", "wildcard-rule", "anyhash1", 1, 1, 1, 1)
	assert.True(t, set.IsIgnored(f3))

	// Legacy
	f4 := createTestFinding("file", "file_content", "legacy/path.py", "", "legacy-rule", "anyhash2", 99, 99, 1, 1)
	assert.True(t, set.IsIgnored(f4))

	// No match
	f5 := createTestFinding("git", "git_patch_content", "no-match.py", "no", "no-match", "nomatch12", 1, 1, 1, 1)
	assert.False(t, set.IsIgnored(f5))
}

// File loading tests

func TestLoadIgnoreFile_MixedFormats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".betterleaksignore")

	content := `# Comment line
git!git_patch_content!path=src/auth.py!aws-access-key!a1b2c3d4!L42-42!C5-25

legacy/path.py:rule-id:10
*!*!*!*!globalha

abc123:path.py:commit-rule:20
`
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)

	set := NewIgnoreSet()
	err = LoadIgnoreFile(path, set)
	require.NoError(t, err)

	// Check exact entry was added
	assert.Contains(t, set.exact, "git!git_patch_content!path=src/auth.py!aws-access-key!a1b2c3d4!L42-42!C5-25")

	// Check matchers were added (wildcard entries)
	assert.True(t, len(set.matchers) > 0 || len(set.unindexed) > 0)
}

func TestLoadIgnoreFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".betterleaksignore")

	err := os.WriteFile(path, []byte(""), 0644)
	require.NoError(t, err)

	set := NewIgnoreSet()
	err = LoadIgnoreFile(path, set)
	require.NoError(t, err)

	assert.Empty(t, set.exact)
	assert.Empty(t, set.matchers)
	assert.Empty(t, set.unindexed)
}
