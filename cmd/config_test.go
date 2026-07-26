package cmd

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
)

// TestValidateConfig_CatchesBrokenRevokeExpr proves that `betterleaks config
// check` (which calls validateConfig) rejects a config whose 'revoke'
// expression has a syntax error, the same way it already rejects a broken
// 'validate' expression. Without this, a config with a typo'd revoke
// expression would pass config check clean, and the error would only surface
// later, mid-revocation, against a real credential.
func TestValidateConfig_CatchesBrokenRevokeExpr(t *testing.T) {
	cfg, err := config.ParseTOMLString(`
[[rules]]
id = "broken-revoke-rule"
regex = '''brk_[a-z0-9]{32}'''
revoke = '''this is not valid expr syntax {{{'''
`, "inline")
	if err != nil {
		t.Fatalf("ParseTOMLString: %v", err)
	}

	err = validateConfig(cfg)
	if err == nil {
		t.Fatal("expected validateConfig to reject a broken revoke expression, got nil error")
	}
	if !strings.Contains(err.Error(), "broken-revoke-rule") {
		t.Errorf("error should name the offending rule, got: %v", err)
	}
	if !strings.Contains(err.Error(), "revocation") {
		t.Errorf("error should mention revocation, got: %v", err)
	}
}

func TestValidateConfig_AcceptsValidRevokeExpr(t *testing.T) {
	cfg, err := config.ParseTOMLString(`
[[rules]]
id = "good-revoke-rule"
regex = '''grr_[a-z0-9]{32}'''
revoke = '''{"result": "revoked"}'''
`, "inline")
	if err != nil {
		t.Fatalf("ParseTOMLString: %v", err)
	}

	if err := validateConfig(cfg); err != nil {
		t.Errorf("expected a valid revoke expression to pass, got: %v", err)
	}
}
