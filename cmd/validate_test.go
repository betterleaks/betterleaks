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

	"github.com/betterleaks/betterleaks/v2/analyze"
	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
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
finding.captures["tenant"] == "acme" &&
finding.secret != "" ? {
  "result": "valid",
  "reason": "tenant=" + finding.captures["tenant"],
  "metadata": {"owner": "alice",
  "echo": "credential=" + finding["secret"],
  "capture_echo": {"tenant": finding.captures["tenant"]},
  "empty": ""}
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
	if len(got.Attributes) != 0 {
		t.Fatalf("attributes = %#v", got.Attributes)
	}
	if got.Analysis.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Analysis.Status)
	}
	if got.Analysis.StatusReason != "tenant=[redacted]" {
		t.Fatalf("sanitized reason = %q", got.Analysis.StatusReason)
	}
	if got.Analysis.StatusMetadata["owner"] != "alice" {
		t.Fatalf("owner metadata = %#v", got.Analysis.StatusMetadata["owner"])
	}
	if got.Analysis.StatusMetadata["echo"] != "credential=[redacted]" {
		t.Fatalf("sanitized metadata = %#v", got.Analysis.StatusMetadata["echo"])
	}
	captureEcho, ok := got.Analysis.StatusMetadata["capture_echo"].(map[string]any)
	if !ok || captureEcho["tenant"] != "[redacted]" {
		t.Fatalf("sanitized capture metadata = %#v", got.Analysis.StatusMetadata["capture_echo"])
	}
	if _, ok := got.Analysis.StatusMetadata["empty"]; ok {
		t.Fatalf("empty metadata was not removed: %#v", got.Analysis.StatusMetadata)
	}
	if strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("JSONL output must be exactly one line: %q", stdout.String())
	}
}

func TestCredentialCommandsAnalysis(t *testing.T) {
	for _, test := range []struct {
		name         string
		command      string
		flags        []string
		status       string
		wantAnalysis bool
	}{
		{name: "analyze pretty", command: "analyze", status: "valid", wantAnalysis: true},
		{name: "analyze jsonl", command: "analyze", flags: []string{"--jsonl"}, status: "valid", wantAnalysis: true},
		{name: "validate pretty", command: "validate", status: "valid"},
		{name: "validate jsonl", command: "validate", flags: []string{"--jsonl"}, status: "valid"},
		{name: "invalid", command: "analyze", flags: []string{"--jsonl"}, status: "invalid"},
		{name: "revoked", command: "analyze", flags: []string{"--jsonl"}, status: "revoked"},
		{name: "unknown", command: "analyze", flags: []string{"--jsonl"}, status: "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/analysis" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				fmt.Fprint(w, `{}`)
			}))
			defer server.Close()
			configPath := writeValidateTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "analysis-token"
regex = '''(unused-regex)'''
validate = '''{"result": %q, "analysis": {"owner": "fixture-owner"}}'''
analyze = '''
let response = http.get(%q, {});
{
  "identity": {"username": validation.analysis.owner},
  "capabilities": ["read"],
  "metadata": {"echo": finding.secret}
}
'''
`, test.status, server.URL+"/analysis"))
			root, stdout := newValidateTestRoot(t)
			args := []string{test.command, "--config", configPath, "--rule-id", "analysis-token", "--no-color"}
			args = append(args, test.flags...)
			root.SetArgs(append(args, "fixture-secret"))
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			wantRequests := int32(0)
			if test.wantAnalysis {
				wantRequests = 1
			}
			if requests.Load() != wantRequests {
				t.Fatalf("analysis requests = %d, want %d", requests.Load(), wantRequests)
			}
			output := stdout.String()
			if strings.Contains(output, "fixture-secret") {
				t.Fatal("analysis report contains the supplied secret")
			}
			if strings.Contains(output, "fixture-owner") != test.wantAnalysis {
				t.Fatalf("unexpected analysis output: %s", output)
			}
			if len(test.flags) > 0 {
				var result report.CredentialReport
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if string(result.Analysis.Status) != test.status || (result.Analysis.Severity != report.SeverityNone) != test.wantAnalysis {
					t.Fatalf("unexpected result: %+v", result)
				}
				if test.wantAnalysis && result.Analysis.Severity != report.SeverityMedium {
					t.Fatalf("severity = %s, want medium", result.Analysis.Severity)
				}
			}
		})
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
	if got.Analysis.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Analysis.Status)
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
validate = '''{"result": "valid", "reason": "Authenticated", "metadata": {"owner": "alice"}}'''
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
len(finding.captures) == 0 &&
components["account-id"].secret == "acct-secret" &&
components["account-id"].captures["region"] == "us" ? {
  "result": "valid",
  "metadata": {"nested": {"component": components["account-id"].secret}}
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
	if got.Analysis.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Analysis.Status)
	}
	if len(got.ComponentSets) != 1 {
		t.Fatalf("component sets = %#v", got.ComponentSets)
	}
	set := got.ComponentSets[0]
	if set.Analysis.Status != report.ValidationStatusValid {
		t.Fatalf("component set status = %q", set.Analysis.Status)
	}
	if len(set.Components) != 1 || set.Components[0].RuleID != "account-id" || set.Components[0].Optional {
		t.Fatalf("components = %#v", set.Components)
	}
	nested, ok := got.Analysis.StatusMetadata["nested"].(map[string]any)
	if !ok || nested["component"] != "[redacted]" {
		t.Fatalf("nested metadata was not sanitized: %#v", got.Analysis.StatusMetadata["nested"])
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
components["required-part"].secret == "required-secret" &&
(components["optional-part"]?.secret ?? "") in ["", "optional-secret"] ? {
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
			if got.Analysis.Status != report.ValidationStatusValid {
				t.Fatalf("status = %q", got.Analysis.Status)
			}
			if len(got.ComponentSets) != 1 {
				t.Fatalf("component sets = %#v", got.ComponentSets)
			}
			components := got.ComponentSets[0].Components
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
components["client-id"].secret == "client-primary" &&
components["client-id"].captures["tenant"] == "acme" ? {
  "result": "valid",
  "metadata": {"echo": finding["secret"] + ":" + components["client-id"].secret}
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
	if got.Analysis.Status != report.ValidationStatusValid {
		t.Fatalf("status = %q", got.Analysis.Status)
	}
	if got.Analysis.StatusMetadata["echo"] != "[redacted]:[redacted]" {
		t.Fatalf("sanitized metadata = %#v", got.Analysis.StatusMetadata["echo"])
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
finding.captures.tenant == "acme" ? {"result": "valid"} : {"result": "invalid"}
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
		"--provider-max-requests", "1",
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
	if got.Analysis.Status != report.ValidationStatusNeedsValidation {
		t.Fatalf("status = %q, metadata = %#v", got.Analysis.Status, got.Analysis.StatusMetadata)
	}
	if requests.Load() != 1 {
		t.Fatalf("provider requests = %d, want 1", requests.Load())
	}
	if got.Analysis.StatusMetadata["betterleaks_max_requests_hit"] != true {
		t.Fatalf("request-limit metadata = %#v", got.Analysis.StatusMetadata)
	}
}

func TestValidateCommandDoesNotExposeOutput(t *testing.T) {
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
		"--output", reportPath,
		"reported-secret",
	})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown flag --output") {
		t.Fatalf("error = %v, want unknown output flag", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if _, statErr := os.Stat(reportPath); !os.IsNotExist(statErr) {
		t.Fatalf("report path was created: %v", statErr)
	}
}

func TestCredentialCommandsRejectInvalidInputs(t *testing.T) {
	configPath := writeValidateTestConfig(t, `
[[rules]]
id = "simple"
regex = '''(simple)'''
validate = '''{"result": "valid"}'''
analyze = '''{"capabilities": ["read"]}'''
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
			args: []string{"validate", "--config", configPath, "--rule-id", "simple", "--provider-debug", "secret"},
			want: "unknown flag --provider-debug",
		},
		{
			name: "list flag",
			args: []string{"validate", "--list"},
			want: "unknown flag --list",
		},
		{
			name: "analysis opt in flag",
			args: []string{"validate", "--with-analysis"},
			want: "unknown flag --with-analysis",
		},
		{
			name: "analysis opt out flag",
			args: []string{"validate", "--no-analysis"},
			want: "unknown flag --no-analysis",
		},
	}

	for _, command := range []string{"validate", "analyze"} {
		for _, test := range tests {
			t.Run(command+"/"+test.name, func(t *testing.T) {
				root, _ := newValidateTestRoot(t)
				root.SetArgs(append([]string{command}, test.args[1:]...))
				err := root.Execute()
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want substring %q", err, test.want)
				}
			})
		}
	}
}

func TestValidateCredentialHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (*analyze.Analyzer)(nil).ValidateCredential(ctx, analyze.Credential{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestReadCredentialInputLimitsStdin(t *testing.T) {
	_, err := readCredentialInput(
		strings.NewReader(strings.Repeat("x", maxCredentialInputBytes+1)),
		&CredentialFlags{},
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want size error", err)
	}
}

type validateTestCLI struct {
	args    []string
	runtime *commandRuntime
}

func (c *validateTestCLI) SetArgs(args []string) { c.args = args }
func (c *validateTestCLI) SetIn(stdin io.Reader) { c.runtime.stdin = stdin }
func (c *validateTestCLI) Execute() error        { return runCLI(c.args, c.runtime) }

func newValidateTestRoot(t *testing.T) (*validateTestCLI, *bytes.Buffer) {
	t.Helper()

	stdout := new(bytes.Buffer)
	runtime := &commandRuntime{
		Context: context.Background(),
		stdin:   os.Stdin,
		stdout:  stdout,
		stderr:  io.Discard,
		exit:    func(int) {},
	}
	return &validateTestCLI{runtime: runtime}, stdout
}

func writeValidateTestConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "betterleaks.toml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestUnknownCredentialRuleErrorSuggestsProviderRules(t *testing.T) {
	cfg := &configpkg.Config{
		Rules: []configpkg.Rule{
			{
				ID:           "github-pat",
				ValidateExpr: `{"result": "valid"}`,
			},
			{
				ID:           "github-oauth",
				ValidateExpr: `{"result": "valid"}`,
			},
			{
				ID: "github-unvalidated",
			},
		},
	}
	err := unknownCredentialRuleError(cfg, "github", false)
	if err == nil || !strings.Contains(err.Error(), "github-pat") || !strings.Contains(err.Error(), "github-oauth") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "github-unvalidated") {
		t.Fatalf("error suggests an unvalidated rule: %v", err)
	}
}

func TestValidateProviderFlagsRejectNegativeTimeout(t *testing.T) {
	err := (ProviderRuntimeFlags{ProviderTimeout: -time.Second}).Validate()
	if err == nil || !strings.Contains(err.Error(), "must be non-negative") {
		t.Fatalf("error = %v", err)
	}
}
