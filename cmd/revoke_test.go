package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

// setRevokeFlags resets revokeCmd's flags to known values before each
// runRevoke invocation, since the command is a shared package-level var.
// It also merges rootCmd's persistent flags (e.g. "no-banner") into its
// local flag set, mirroring what cobra normally does inside Execute() -
// initConfig reads "no-banner" via rootCmd.Flags(), which is otherwise
// unpopulated when a Run function is invoked directly, bypassing Execute().
func setRevokeFlags(t *testing.T, fingerprint string, yes, dryRun, continueOnError bool, output string) {
	t.Helper()
	if err := rootCmd.ParseFlags(nil); err != nil {
		t.Fatalf("merging root flags: %v", err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("setting flag: %v", err)
		}
	}
	must(revokeCmd.Flags().Set("fingerprint", fingerprint))
	must(revokeCmd.Flags().Set("yes", fmtBool(yes)))
	must(revokeCmd.Flags().Set("dry-run", fmtBool(dryRun)))
	must(revokeCmd.Flags().Set("continue-on-error", fmtBool(continueOnError)))
	must(revokeCmd.Flags().Set("output", output))
}

func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestRunRevoke_FingerprintFilterPreservesFullReportInOutput proves that
// filtering by --fingerprint no longer truncates the --output report to just
// the matched finding: every other finding from the original report must
// still be present, untouched, in the written output.
func TestRunRevoke_FingerprintFilterPreservesFullReportInOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	revokeExpr := `let r = http.delete("` + srv.URL + `", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error"}`
	t.Setenv("BETTERLEAKS_CONFIG_TOML", `
[[rules]]
id = "revocable-rule"
regex = '''rr_[a-z0-9]{32}'''
revoke = '''`+revokeExpr+`'''
`)

	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	outputPath := filepath.Join(dir, "out.json")
	original := []report.Finding{
		{RuleID: "revocable-rule", Secret: "rr_target_secret", Fingerprint: "target-fp"},
		{RuleID: "revocable-rule", Secret: "rr_other_secret_1", Fingerprint: "other-fp-1"},
		{RuleID: "revocable-rule", Secret: "rr_other_secret_2", Fingerprint: "other-fp-2"},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	setRevokeFlags(t, "target-fp", true, false, false, outputPath)
	initConfig(".")
	runRevoke(revokeCmd, []string{reportPath})

	out, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	var got []report.Finding
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if len(got) != len(original) {
		t.Fatalf("output has %d findings, want %d (all of them, not just the fingerprint-matched one)", len(got), len(original))
	}
	byFP := map[string]report.Finding{}
	for _, f := range got {
		byFP[f.Fingerprint] = f
	}
	if byFP["target-fp"].ValidationStatus != report.ValidationStatusRevoked {
		t.Errorf("targeted finding should be marked revoked, got status %q", byFP["target-fp"].ValidationStatus)
	}
	if byFP["other-fp-1"].ValidationStatus == report.ValidationStatusRevoked {
		t.Errorf("untargeted finding other-fp-1 should not have been touched")
	}
	if byFP["other-fp-2"].ValidationStatus == report.ValidationStatusRevoked {
		t.Errorf("untargeted finding other-fp-2 should not have been touched")
	}
}

// TestRunRevoke_OutputFileIsNotWorldReadable proves the --output report,
// which can contain live/revoked secrets in plaintext, is written with a
// restrictive mode rather than the world/group-readable 0644.
func TestRunRevoke_OutputFileIsNotWorldReadable(t *testing.T) {
	if isWindows() {
		t.Skip("POSIX file mode bits are not meaningful on Windows")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	revokeExpr := `let r = http.delete("` + srv.URL + `", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error"}`
	t.Setenv("BETTERLEAKS_CONFIG_TOML", `
[[rules]]
id = "revocable-rule"
regex = '''rr_[a-z0-9]{32}'''
revoke = '''`+revokeExpr+`'''
`)

	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	outputPath := filepath.Join(dir, "out.json")
	data, _ := json.Marshal([]report.Finding{{RuleID: "revocable-rule", Secret: "rr_secret", Fingerprint: "fp"}})
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	setRevokeFlags(t, "", true, false, false, outputPath)
	initConfig(".")
	runRevoke(revokeCmd, []string{reportPath})

	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("output file mode = %o, want no group/world permission bits (e.g. 0600)", mode)
	}
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

// TestRunRevoke_WritesOutputBeforeExitingOnFailure proves that when an
// earlier finding is successfully revoked and a later one fails (without
// --continue-on-error, so the process exits), the already-successful,
// irreversible revocation is still recorded in --output before the process
// exits. This runs the real command in a subprocess since a failed
// revocation calls os.Exit(1).
func TestRunRevoke_WritesOutputBeforeExitingOnFailure(t *testing.T) {
	if os.Getenv("BETTERLEAKS_REVOKE_HELPER") == "1" {
		reportPath := os.Getenv("HELPER_REPORT_PATH")
		outputPath := os.Getenv("HELPER_OUTPUT_PATH")
		setRevokeFlags(t, "", true, false, false, outputPath)
		initConfig(".")
		runRevoke(revokeCmd, []string{reportPath})
		return
	}

	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer okSrv.Close()
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failSrv.Close()

	okExpr := `let r = http.delete("` + okSrv.URL + `", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error"}`
	failExpr := `let r = http.delete("` + failSrv.URL + `", {"Authorization": "Bearer " + secret}); r.status == 204 ? {"result": "revoked"} : {"result": "error", "reason": "boom"}`

	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	outputPath := filepath.Join(dir, "out.json")
	findings := []report.Finding{
		{RuleID: "ok-rule", Secret: "ok_secret", Fingerprint: "ok-fp"},
		{RuleID: "fail-rule", Secret: "fail_secret", Fingerprint: "fail-fp"},
	}
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunRevoke_WritesOutputBeforeExitingOnFailure")
	cmd.Env = append(os.Environ(),
		"BETTERLEAKS_REVOKE_HELPER=1",
		"HELPER_REPORT_PATH="+reportPath,
		"HELPER_OUTPUT_PATH="+outputPath,
		`BETTERLEAKS_CONFIG_TOML=`+`
[[rules]]
id = "ok-rule"
regex = '''ok_[a-z0-9]*'''
revoke = '''`+okExpr+`'''

[[rules]]
id = "fail-rule"
regex = '''fail_[a-z0-9]*'''
revoke = '''`+failExpr+`'''
`,
	)
	runErr := cmd.Run()
	if runErr == nil {
		t.Fatal("expected the subprocess to exit non-zero (a revocation failed), got nil error")
	}

	out, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading output (expected it to be written before exiting): %v", err)
	}
	var got []report.Finding
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	byFP := map[string]report.Finding{}
	for _, f := range got {
		byFP[f.Fingerprint] = f
	}
	if byFP["ok-fp"].ValidationStatus != report.ValidationStatusRevoked {
		t.Errorf("the successful revocation before the failure should still be recorded in --output, got status %q", byFP["ok-fp"].ValidationStatus)
	}
}
