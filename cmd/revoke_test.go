package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
)

func testConfig(t *testing.T, revokeExpr string) *config.Config {
	t.Helper()
	toml := `
[[rules]]
id = "revocable-rule"
regex = '''rr_[a-z0-9]{32}'''
`
	if revokeExpr != "" {
		toml += "revoke = '''" + revokeExpr + "'''\n"
	}
	toml += `
[[rules]]
id = "no-revoke-rule"
regex = '''nrr_[a-z0-9]{32}'''
`
	cfg, err := config.ParseTOMLString(toml, "inline")
	if err != nil {
		t.Fatalf("ParseTOMLString: %v", err)
	}
	return cfg
}

func TestRevokeOne_UnsupportedWhenRuleHasNoRevokeExpr(t *testing.T) {
	cfg := testConfig(t, "")
	f := &report.Finding{RuleID: "no-revoke-rule", Secret: "whatever"}

	attempt := revokeOne(context.Background(), cfg, nil, f)
	if attempt.Outcome != outcomeUnsupported {
		t.Errorf("Outcome = %v, want %v", attempt.Outcome, outcomeUnsupported)
	}
}

func TestRevokeOne_UnsupportedWhenRuleUnknown(t *testing.T) {
	cfg := testConfig(t, "")
	f := &report.Finding{RuleID: "does-not-exist", Secret: "whatever"}

	attempt := revokeOne(context.Background(), cfg, nil, f)
	if attempt.Outcome != outcomeUnsupported {
		t.Errorf("Outcome = %v, want %v", attempt.Outcome, outcomeUnsupported)
	}
}

func TestRevokeOne_SuccessCallsProviderAndReturnsRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer rr_test_secret" {
			t.Errorf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	revokeExpr := `let r = http.delete("` + srv.URL + `", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error", "reason": "unexpected status"}`
	cfg := testConfig(t, revokeExpr)
	runtime, err := cfg.CompileRevocation()
	if err != nil {
		t.Fatalf("CompileRevocation: %v", err)
	}
	f := &report.Finding{RuleID: "revocable-rule", Secret: "rr_test_secret"}

	attempt := revokeOne(context.Background(), cfg, runtime, f)
	if attempt.Outcome != outcomeRevoked {
		t.Fatalf("Outcome = %v, want %v (err=%v, reason=%v)", attempt.Outcome, outcomeRevoked, attempt.Err, attempt.Reason)
	}
}

func TestRevokeOne_ProviderErrorDoesNotYieldRevoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	revokeExpr := `let r = http.delete("` + srv.URL + `", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error", "reason": "provider returned an error"}`
	cfg := testConfig(t, revokeExpr)
	runtime, err := cfg.CompileRevocation()
	if err != nil {
		t.Fatalf("CompileRevocation: %v", err)
	}
	f := &report.Finding{RuleID: "revocable-rule", Secret: "rr_test_secret"}

	attempt := revokeOne(context.Background(), cfg, runtime, f)
	if attempt.Outcome != outcomeFailed {
		t.Fatalf("Outcome = %v, want %v", attempt.Outcome, outcomeFailed)
	}
	if attempt.Reason != "provider returned an error" {
		t.Errorf("Reason = %q", attempt.Reason)
	}
}

func TestRevokeOne_CompileErrorIsFailedNotPanic(t *testing.T) {
	cfg := testConfig(t, `this is not valid expr syntax {{{`)
	runtime, err := cfg.CompileRevocation()
	if err != nil {
		t.Fatalf("CompileRevocation: %v", err)
	}
	f := &report.Finding{RuleID: "revocable-rule", Secret: "rr_test_secret"}

	attempt := revokeOne(context.Background(), cfg, runtime, f)
	if attempt.Outcome != outcomeFailed {
		t.Fatalf("Outcome = %v, want %v", attempt.Outcome, outcomeFailed)
	}
	if attempt.Err == nil {
		t.Error("expected a compile error to be set on Err")
	}
}

func TestLoadFindingsReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	want := []report.Finding{
		{RuleID: "revocable-rule", Secret: "rr_test_secret", Fingerprint: "abc123"},
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := loadFindingsReport(path)
	if err != nil {
		t.Fatalf("loadFindingsReport: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "revocable-rule" || got[0].Fingerprint != "abc123" {
		t.Errorf("got %+v", got)
	}
}

func TestLoadFindingsReport_MissingFile(t *testing.T) {
	_, err := loadFindingsReport(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestLoadFindingsReport_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := loadFindingsReport(path)
	if err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

func TestShortFingerprint(t *testing.T) {
	tests := []struct{ in, want string }{
		{"short", "short"},
		{"exactly12ch1", "exactly12ch1"},
		{"this-is-a-very-long-fingerprint", "this-is-a-ve…"},
	}
	for _, tc := range tests {
		if got := shortFingerprint(tc.in); got != tc.want {
			t.Errorf("shortFingerprint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNonEmptyOr(t *testing.T) {
	if got := nonEmptyOr("", "fallback"); got != "fallback" {
		t.Errorf("got %q, want fallback", got)
	}
	if got := nonEmptyOr("value", "fallback"); got != "value" {
		t.Errorf("got %q, want value", got)
	}
}
