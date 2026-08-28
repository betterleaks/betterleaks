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

	"github.com/spf13/cobra"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func TestValidateCommandJSONL(t *testing.T) {
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
  "reason": "tenant=" + captures["tenant"],
  "owner": "alice",
  "echo": "credential=" + finding["secret"],
  "capture_echo": {"tenant": captures["tenant"]},
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
		"--jsonl",
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
	if got.Attributes[sources.AttrPath] != "betterleaks://validate" {
		t.Fatalf("attributes = %#v", got.Attributes)
	}
	if got.Validation.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Validation.Status)
	}
	if got.Validation.Reason != "tenant=[redacted]" {
		t.Fatalf("sanitized reason = %q", got.Validation.Reason)
	}
	if got.Validation.Metadata["owner"] != "alice" {
		t.Fatalf("owner metadata = %#v", got.Validation.Metadata["owner"])
	}
	if got.Validation.Metadata["echo"] != "credential=[redacted]" {
		t.Fatalf("sanitized metadata = %#v", got.Validation.Metadata["echo"])
	}
	captureEcho, ok := got.Validation.Metadata["capture_echo"].(map[string]any)
	if !ok || captureEcho["tenant"] != "[redacted]" {
		t.Fatalf("sanitized capture metadata = %#v", got.Validation.Metadata["capture_echo"])
	}
	if _, ok := got.Validation.Metadata["empty"]; ok {
		t.Fatalf("empty metadata was not removed: %#v", got.Validation.Metadata)
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("JSONL output must be exactly one line: %q", stdout.String())
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
		"--jsonl",
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

components = [{ id = "account-id" }]
`)

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "account-secret",
		"--component", "account-id=acct-secret",
		"--capture", "account-id:region=us",
		"--jsonl",
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
	if len(got.Validation.ComponentSets) != 1 {
		t.Fatalf("component sets = %#v", got.Validation.ComponentSets)
	}
	set := got.Validation.ComponentSets[0]
	if set.Status != report.ValidationStatusValid {
		t.Fatalf("component set status = %q", set.Status)
	}
	if len(set.Components) != 1 || set.Components[0].RuleID != "account-id" || set.Components[0].Optional {
		t.Fatalf("components = %#v", set.Components)
	}
	nested, ok := got.Validation.Metadata["nested"].(map[string]any)
	if !ok || nested["component"] != "[redacted]" {
		t.Fatalf("nested metadata was not sanitized: %#v", got.Validation.Metadata["nested"])
	}
}

func TestValidateCommandOptionalComponents(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "required-part"
regex = '''(required-part)'''
skipReport = true

[[rules]]
id = "optional-part"
regex = '''(optional-part)'''
skipReport = true

[[rules]]
id = "primary"
regex = '''(primary)'''
components = [
  { id = "required-part" },
  { id = "optional-part", optional = true },
]
validate = '''
captures["required-part"] == "required-secret" &&
get(captures, "optional-part", "") in ["", "optional-secret"] ? {
  "result": "valid"
} : {
  "result": "invalid"
}
'''
`)

	tests := []struct {
		name               string
		componentArguments []string
		wantOptional       bool
	}{
		{
			name:               "optional component omitted",
			componentArguments: []string{"--component", "required-part=required-secret"},
		},
		{
			name: "optional component supplied",
			componentArguments: []string{
				"--component", "required-part=required-secret",
				"--component", "optional-part=optional-secret",
			},
			wantOptional: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, stdout := newValidateTestRoot(t)
			args := []string{
				"validate",
				"--config", configPath,
				"--rule-id", "primary",
				"--jsonl",
			}
			args = append(args, test.componentArguments...)
			args = append(args, "primary-secret")
			root.SetArgs(args)
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
			if len(got.Validation.ComponentSets) != 1 {
				t.Fatalf("component sets = %#v", got.Validation.ComponentSets)
			}
			components := got.Validation.ComponentSets[0].Components
			present, optional := findCredentialComponent(components, "optional-part")
			if present != test.wantOptional {
				t.Fatalf("optional component present = %t, want %t; components = %#v", present, test.wantOptional, components)
			}
			if present && !optional {
				t.Fatalf("optional component was reported as required: %#v", components)
			}
		})
	}

	root, _ := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "primary",
		"--component", "optional-part=optional-secret",
		"primary-secret",
	})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "missing required component(s): required-part") {
		t.Fatalf("error = %v, want missing required component", err)
	}
}

func findCredentialComponent(components []report.CredentialComponentReport, ruleID string) (present, optional bool) {
	for _, component := range components {
		if component.RuleID == ruleID {
			return true, component.Optional
		}
	}
	return false, false
}

func TestValidateCommandReadsMultipartPrimaryFromStdin(t *testing.T) {
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

components = [{ id = "client-id" }]
`)

	root, stdout := newValidateTestRoot(t)
	root.SetIn(strings.NewReader("secret-primary\n"))
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "client-secret",
		"--component", "client-id=client-primary",
		"--capture", "client-id:tenant=acme",
		"--jsonl",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}

	if strings.Contains(stdout.String(), "secret-primary") || strings.Contains(stdout.String(), "client-primary") {
		t.Fatalf("report contains supplied credential input: %s", stdout.String())
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

func TestValidateCommandTreatsJSONStdinAsPrimarySecret(t *testing.T) {
	const credential = `{"type":"authorized_user","client_id":"fake.apps.googleusercontent.com","client_secret":"fake-secret","refresh_token":"fake-refresh"}`
	configPath := writeValidateTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "json-credential"
regex = '''(json-credential)'''
validate = '''
finding["secret"] == %q ? {"result": "valid"} : {"result": "invalid"}
'''
`, credential))

	root, stdout := newValidateTestRoot(t)
	root.SetIn(strings.NewReader(credential + "\n"))
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "json-credential",
		"--simple",
		"--no-color",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command: %v", err)
	}
	if got, want := stdout.String(), "VALID\n"; got != want {
		t.Fatalf("simple output = %q, want %q", got, want)
	}
}

func TestValidateCommandRequiresReferencedNamedCaptures(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "capture-dependent"
regex = '''(?P<tenant>[a-z]+)-(?P<id>[a-z]+)-(?P<credential>secret-[a-z]+)'''
secretGroup = 3
validate = '''
(finding["captures"]?.tenant ?? "") == "acme" ? {"result": "valid"} : {"result": "invalid"}
'''
`)

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "capture-dependent",
		"secret-value",
	})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "missing required capture(s)") || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("error = %v, want missing tenant capture", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}

	root, stdout = newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "capture-dependent",
		"--capture", "tenant=acme",
		"--simple",
		"--no-color",
		"secret-value",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("validate command with required capture: %v", err)
	}
	if got, want := stdout.String(), "VALID\n"; got != want {
		t.Fatalf("simple output = %q, want %q", got, want)
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
		"--jsonl",
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

func TestValidateCommandDoesNotExposeReportPath(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "reported-token"
regex = '''(reported-token)'''
validate = '''{"result": "invalid", "reason": "Unauthorized"}'''
`)
	reportPath := filepath.Join(t.TempDir(), "credential.jsonl")

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule-id", "reported-token",
		"--report", reportPath,
		"reported-secret",
	})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --report") {
		t.Fatalf("error = %v, want unknown report flag", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if _, statErr := os.Stat(reportPath); !os.IsNotExist(statErr) {
		t.Fatalf("report path was created: %v", statErr)
	}
}

func TestValidateCommandListsOnlyRulesWithValidation(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "component"
regex = '''(component)'''
skipReport = true

[[rules]]
id = "optional-component"
regex = '''(optional-component)'''
skipReport = true

[[rules]]
id = "validated"
description = "Validated rule"
regex = '''(?P<context>context)-(validated)'''
secretGroup = 2
validate = '''(finding["captures"]?.context ?? "") != "" ? {"result": "valid"} : {"result": "invalid"}'''

components = [
  { id = "component" },
  { id = "optional-component", optional = true },
]

[[rules]]
id = "unvalidated"
regex = '''(unvalidated)'''
`)

	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--list",
		"--jsonl",
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
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("JSONL rule list must be exactly one line: %q", stdout.String())
	}
	if len(got.Rules[0].Components) != 2 {
		t.Fatalf("components = %#v", got.Rules[0].Components)
	}
	if got.Rules[0].Components[0].RuleID != "component" || got.Rules[0].Components[0].Optional {
		t.Fatalf("required component = %#v", got.Rules[0].Components[0])
	}
	if got.Rules[0].Components[1].RuleID != "optional-component" || !got.Rules[0].Components[1].Optional {
		t.Fatalf("optional component = %#v", got.Rules[0].Components[1])
	}
	if len(got.Rules[0].Captures) != 1 || got.Rules[0].Captures[0] != "context" {
		t.Fatalf("required captures = %#v", got.Rules[0].Captures)
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
			want: "not declared",
		},
		{
			name: "duplicate capture",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--capture", "name=one", "--capture", "name=two", "secret"},
			want: "supplied more than once",
		},
		{
			name: "simple JSONL report",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--simple", "--jsonl", "secret"},
			want: "--simple cannot be combined",
		},
		{
			name: "validation debug",
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--validation-debug", "secret"},
			want: "unknown flag: --validation-debug",
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
	_, err := evaluateCredential(ctx, nil, nil, report.Finding{})
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

	root := &cobra.Command{
		Use:           "betterleaks",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.PersistentFlags().String("config", "", "")
	root.PersistentFlags().Bool("no-color", false, "")
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
	if err := validateCmd.Flags().Set("validation-timeout", "-1s"); err != nil {
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
