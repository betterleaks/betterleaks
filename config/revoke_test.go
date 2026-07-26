package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevokeExpr_Parsed(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "example-token"
regex = '''example_[a-z0-9]{32}'''
revoke = '''let r = http.delete("https://api.example.com/token", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error", "reason": "unexpected status"}'''
`, "inline")
	require.NoError(t, err)

	rule, ok := cfg.Rules["example-token"]
	require.True(t, ok)
	assert.Contains(t, rule.RevokeExpr, `http.delete`)
	assert.Empty(t, rule.ValidateExpr, "revoke and validate are independent fields")
}

func TestRevokeExpr_AbsentWhenNotConfigured(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "no-revoke-rule"
regex = '''nrr_[a-z0-9]{32}'''
`, "inline")
	require.NoError(t, err)

	rule, ok := cfg.Rules["no-revoke-rule"]
	require.True(t, ok)
	assert.Empty(t, rule.RevokeExpr)
}

// TestRevokeExpr_ExtendedRuleOverridesBase exercises the real [extend] merge
// path (the same mechanism covered by TestTranslateExtend for other rule
// fields) to confirm RevokeExpr participates in it correctly: an extending
// rule's non-empty RevokeExpr replaces the base rule's, mirroring how
// ValidateExpr already behaves.
func TestRevokeExpr_ExtendedRuleOverridesBase(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.toml")
	extendPath := filepath.Join(dir, "extend.toml")

	require.NoError(t, os.WriteFile(basePath, []byte(`
[[rules]]
id = "extend-me"
regex = '''em_[a-z0-9]{32}'''
revoke = '''{"result": "revoked", "reason": "base"}'''
`), 0o600))

	require.NoError(t, os.WriteFile(extendPath, []byte(`
[extend]
path = "`+filepath.ToSlash(basePath)+`"

[[rules]]
id = "extend-me"
revoke = '''{"result": "revoked", "reason": "overridden"}'''
`), 0o600))

	cfg, err := LoadFile(extendPath)
	require.NoError(t, err)

	rule, ok := cfg.Rules["extend-me"]
	require.True(t, ok)
	assert.Contains(t, rule.RevokeExpr, "overridden")
	assert.NotContains(t, rule.RevokeExpr, `"reason": "base"`)
}

func TestCompileRevocation_NilWhenNoRulesDefineRevoke(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "plain-rule"
regex = '''pr_[a-z0-9]{32}'''
`, "inline")
	require.NoError(t, err)

	runtime, err := cfg.CompileRevocation()
	require.NoError(t, err)
	assert.Nil(t, runtime, "no rule defines a revoke expression, so no runtime should be created")
}

func TestCompileRevocation_CreatesRuntimeWhenAnyRuleDefinesRevoke(t *testing.T) {
	cfg, err := ParseTOMLString(`
[[rules]]
id = "plain-rule"
regex = '''pr_[a-z0-9]{32}'''

[[rules]]
id = "revocable-rule"
regex = '''rr_[a-z0-9]{32}'''
revoke = '''{"result": "revoked"}'''
`, "inline")
	require.NoError(t, err)

	runtime, err := cfg.CompileRevocation()
	require.NoError(t, err)
	require.NotNil(t, runtime)

	prg, err := runtime.CompileValidation(cfg.Rules["revocable-rule"].RevokeExpr)
	require.NoError(t, err)
	assert.NotNil(t, prg)
}
