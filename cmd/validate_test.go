package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/report"
)

func TestValidateCommandJSON(t *testing.T) {
	const secret = "live-secret"
	configPath := writeValidateTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "test-token"
description = "A test credential"
regex = '''(test-token)'''
validate = '''
finding["secret"] == %q &&
captures["tenant"] == "acme" &&
attributes["path"] == "betterleaks://validate" ? {
  "result": "valid",
  "owner": "alice",
  "echo": "credential=" + finding["secret"],
  "empty": ""
} : {
  "result": "invalid"
}
'''
`, secret))

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "test-token",
		"--capture", "tenant=acme",
		"--report-format", "json",
		secret,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	if strings.Contains(stdout.String(), secret) {
		t.Fatalf("report contains supplied secret: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), `"description"`) {
		t.Fatalf("validation report contains a rule description: %s", stdout.String())
	}
	var got report.CredentialReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if got.SchemaVersion != report.CredentialReportSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got.SchemaVersion, report.CredentialReportSchemaVersion)
	}
	if got.RuleID != "test-token" {
		t.Fatalf("rule ID = %q", got.RuleID)
	}
	if got.Validation.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Validation.Status)
	}
	if got.Validation.Metadata["owner"] != "alice" {
		t.Fatalf("owner metadata = %#v", got.Validation.Metadata["owner"])
	}
	if got.Validation.Metadata["echo"] != "credential=[redacted]" {
		t.Fatalf("sanitized metadata = %#v", got.Validation.Metadata["echo"])
	}
	if _, ok := got.Validation.Metadata["empty"]; ok {
		t.Fatalf("empty metadata was not removed: %#v", got.Validation.Metadata)
	}
}

func TestValidateCommandReadsSecretFromStdin(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "stdin-token"
regex = '''(stdin-token)'''
validate = '''
finding["secret"] == "from-stdin" ? {"result": "valid"} : {"result": "invalid"}
'''
`)

	root, stdout := newValidateTestRoot(t)
	root.SetIn(strings.NewReader("from-stdin\n"))
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "stdin-token",
		"--report-format", "json",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	var got report.CredentialReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if got.Validation.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Validation.Status)
	}
	if strings.Contains(stdout.String(), "from-stdin") {
		t.Fatalf("report contains supplied secret: %s", stdout.String())
	}
}

func TestValidateCommandSimple(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "simple-token"
regex = '''(simple-token)'''
validate = '''{"result": "valid", "reason": "Authenticated", "owner": "alice"}'''
`)

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "simple-token",
		"--simple",
		"--no-color",
		"simple-secret",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	if got, want := stdout.String(), "VALID\n"; got != want {
		t.Fatalf("simple output = %q, want %q", got, want)
	}
}

func TestValidateCommandCompositeCredential(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "account-id"
description = "Account identifier component"
regex = '''(acct-[a-z]+)'''
skipReport = true

[[rules]]
id = "account-secret"
description = "Composite account credential"
regex = '''(secret-[a-z]+)'''
validate = '''
captures["account-id"] == "acct-secret" &&
captures["account-id:region"] == "us" ? {
  "result": "valid",
  "nested": {"component": captures["account-id"]}
} : {
  "result": "invalid"
}
'''

[[rules.required]]
id = "account-id"
`)

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "account-secret",
		"--component", "account-id=acct-secret",
		"--capture", "account-id:region=us",
		"--report-format", "json",
		"secret-primary",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	if strings.Contains(stdout.String(), "secret-primary") || strings.Contains(stdout.String(), "acct-secret") {
		t.Fatalf("report contains a supplied credential component: %s", stdout.String())
	}
	var got report.CredentialReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if got.Validation.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Validation.Status)
	}
	if len(got.Validation.RequiredSets) != 1 {
		t.Fatalf("required sets = %#v", got.Validation.RequiredSets)
	}
	set := got.Validation.RequiredSets[0]
	if set.Status != report.ValidationStatusValid {
		t.Fatalf("required set status = %q", set.Status)
	}
	if len(set.Components) != 1 || set.Components[0] != "account-id" {
		t.Fatalf("components = %#v", set.Components)
	}
	nested, ok := got.Validation.Metadata["nested"].(map[string]any)
	if !ok || nested["component"] != "[redacted]" {
		t.Fatalf("nested metadata was not sanitized: %#v", got.Validation.Metadata["nested"])
	}
}

func TestValidateCommandReadsStructuredCredentialFromStdin(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "client-id"
regex = '''(client-[a-z]+)'''
skipReport = true

[[rules]]
id = "client-secret"
regex = '''(secret-[a-z]+)'''
validate = '''
finding["secret"] == "secret-primary" &&
captures["client-id"] == "client-primary" &&
captures["client-id:tenant"] == "acme" ? {
  "result": "valid",
  "echo": finding["secret"] + ":" + captures["client-id"]
} : {
  "result": "invalid"
}
'''

[[rules.required]]
id = "client-id"
`)

	root, stdout := newValidateTestRoot(t)
	root.SetIn(strings.NewReader(`{
  "secret": "secret-primary",
  "components": {"client-id": "client-primary"},
  "captures": {"client-id:tenant": "acme"}
}`))
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "client-secret",
		"--report-format", "json",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	if strings.Contains(stdout.String(), "secret-primary") || strings.Contains(stdout.String(), "client-primary") {
		t.Fatalf("report contains structured credential input: %s", stdout.String())
	}
	var got report.CredentialReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if got.Validation.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Validation.Status)
	}
	if got.Validation.Metadata["echo"] != "[redacted]:[redacted]" {
		t.Fatalf("sanitized metadata = %#v", got.Validation.Metadata["echo"])
	}
}

func TestDecodeValidateCredentialInputRejectsAttributes(t *testing.T) {
	_, err := decodeValidateCredentialInput([]byte(`{
  "secret": "secret-primary",
  "attributes": {"region": "eu"}
}`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "attributes"`) {
		t.Fatalf("error = %v, want unknown attributes field", err)
	}
}

func TestValidateCommandHonorsRequestLimit(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	configPath := writeValidateTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "limited-token"
regex = '''(limited-token)'''
validate = '''
let r1 = http.get(%q, {});
let r2 = http.get(%q, {});
{"result": "valid", "statuses": [r1.status, r2.status]}
'''
`, server.URL+"/first", server.URL+"/second"))

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "limited-token",
		"--validation-max-requests", "1",
		"--report-format", "json",
		"limited-secret",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	var got report.CredentialReport
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if got.Validation.Status != report.ValidationStatusNeedsValidation {
		t.Fatalf("status = %q, metadata = %#v", got.Validation.Status, got.Validation.Metadata)
	}
	if requests.Load() != 1 {
		t.Fatalf("provider requests = %d, want 1", requests.Load())
	}
	if got.Validation.Metadata["betterleaks_max_requests_hit"] != true {
		t.Fatalf("request-limit metadata = %#v", got.Validation.Metadata)
	}
}

func TestValidateCommandWritesPrivateJSONReport(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "reported-token"
regex = '''(reported-token)'''
validate = '''{"result": "invalid", "reason": "Unauthorized"}'''
`)
	reportPath := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(reportPath, []byte(`{"old":"report"}`), 0o644); err != nil {
		t.Fatalf("write existing report: %v", err)
	}
	if err := os.Chmod(reportPath, 0o644); err != nil {
		t.Fatalf("make existing report permissive: %v", err)
	}

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "reported-token",
		"--report-path", reportPath,
		"reported-secret",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if strings.Contains(string(data), "reported-secret") {
		t.Fatalf("report contains supplied secret: %s", data)
	}
	var got report.CredentialReport
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("report path did not infer JSON: %v\n%s", err, data)
	}
	if got.Validation.Status != report.ValidationStatusInvalid {
		t.Fatalf("status = %q", got.Validation.Status)
	}
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("report permissions = %o, want 600", gotMode)
	}
}

func TestValidateCommandListsOnlyRulesWithValidation(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "component"
regex = '''(component)'''
skipReport = true

[[rules]]
id = "validated"
description = "Validated rule"
regex = '''(validated)'''
validate = '''{"result": "valid"}'''

[[rules.required]]
id = "component"

[[rules]]
id = "unvalidated"
regex = '''(unvalidated)'''
`)

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--list",
		"--report-format", "json",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate --list: %v", err)
	}

	var got report.CredentialRuleList
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].RuleID != "validated" {
		t.Fatalf("listed rules = %#v", got.Rules)
	}
	if len(got.Rules[0].RequiredComponents) != 1 || got.Rules[0].RequiredComponents[0] != "component" {
		t.Fatalf("required components = %#v", got.Rules[0].RequiredComponents)
	}
}

func TestValidateCommandRejectsInvalidInputs(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "simple"
regex = '''(simple)'''
validate = '''{"result": "valid"}'''
`)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing rule",
			args: []string{"validate", "--config", configPath, "secret"},
			want: "--rule-id is required",
		},
		{
			name: "missing secret",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple"},
			want: "secret argument or piped credential is required",
		},
		{
			name: "extra component",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--component", "other=value", "secret"},
			want: "not required",
		},
		{
			name: "duplicate capture",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--capture", "name=one", "--capture", "name=two", "secret"},
			want: "supplied more than once",
		},
		{
			name: "unsupported report",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--report-format", "sarif", "secret"},
			want: "must be text or json",
		},
		{
			name: "simple JSON report",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--simple", "--report-format", "json", "secret"},
			want: "--simple only supports text output",
		},
		{
			name: "list with rule",
			args: []string{"validate", "--config", configPath, "--list", "--rule-id", "simple"},
			want: "cannot be combined",
		},
		{
			name: "list with simple",
			args: []string{"validate", "--config", configPath, "--list", "--simple"},
			want: "cannot be combined",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, _ := newValidateTestRoot(t)
			root.SetArgs(test.args)
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestEvaluateCredentialHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := evaluateCredential(ctx, nil, nil, report.Finding{}, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestReadValidateCredentialInputLimitsStdin(t *testing.T) {
	cmd := newValidateCmd()
	cmd.SetIn(strings.NewReader(strings.Repeat("x", maxValidateCredentialInputBytes+1)))
	_, err := readValidateCredentialInput(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want size error", err)
	}
}

func newValidateTestRoot(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	// Package-level Cobra initializers read flags from rootCmd. Merge its
	// persistent flags before executing an isolated test command tree.
	if err := rootCmd.ParseFlags(nil); err != nil {
		t.Fatalf("initialize package root flags: %v", err)
	}

	root := &cobra.Command{
		Use:           "betterleaks",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().String("report-path", "", "")
	root.PersistentFlags().String("report-format", "", "")
	root.PersistentFlags().String("report-template", "", "")
	root.PersistentFlags().Bool("no-color", false, "")
	root.PersistentFlags().Duration("validation-timeout", 10*time.Second, "")
	root.PersistentFlags().Int("validation-max-requests", 0, "")
	root.PersistentFlags().Int("validation-max-request", 0, "")
	root.PersistentFlags().Float64("validation-rps", 0, "")
	root.PersistentFlags().StringSlice("validation-rps-rule", nil, "")
	root.PersistentFlags().StringSlice("validation-env-vars", nil, "")
	root.PersistentFlags().Bool("validation-debug", false, "")
	root.PersistentFlags().Bool("validation-extract-empty", false, "")
	root.AddCommand(newValidateCmd())

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(io.Discard)
	return root, &stdout
}

func writeValidateTestConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "betterleaks.toml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestUnknownValidationRuleErrorSuggestsProviderRules(t *testing.T) {
	cfg := &configpkg.Config{
		Rules: map[string]configpkg.Rule{
			"github-pat": {
				RuleID:       "github-pat",
				ValidateExpr: `{"result": "valid"}`,
			},
			"github-oauth": {
				RuleID:       "github-oauth",
				ValidateExpr: `{"result": "valid"}`,
			},
			"github-unvalidated": {
				RuleID: "github-unvalidated",
			},
		},
		OrderedRules: []string{"github-pat", "github-oauth", "github-unvalidated"},
	}
	err := unknownValidationRuleError(cfg, "github")
	if err == nil || !strings.Contains(err.Error(), "github-pat") || !strings.Contains(err.Error(), "github-oauth") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "github-unvalidated") {
		t.Fatalf("error suggests an unvalidated rule: %v", err)
	}
}

func TestConfigureCredentialRuntimeRejectsNegativeTimeout(t *testing.T) {
	root, _ := newValidateTestRoot(t)
	validateCmd, _, err := root.Find([]string{"validate"})
	if err != nil {
		t.Fatalf("find validate command: %v", err)
	}
	if err := root.PersistentFlags().Set("validation-timeout", "-1s"); err != nil {
		t.Fatalf("set timeout: %v", err)
	}
	if err := validateCmd.ParseFlags(nil); err != nil {
		t.Fatalf("merge inherited flags: %v", err)
	}
	runtime, err := exprruntime.New(nil)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	err = configureCredentialRuntime(validateCmd, runtime)
	if err == nil || !strings.Contains(err.Error(), "must be non-negative") {
		t.Fatalf("error = %v", err)
	}
}
