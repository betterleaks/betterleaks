package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCommandJSONL(t *testing.T) {
	const secret = "live-secret"
	configPath := writeTestConfig(t, fmt.Sprintf(`
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

	root, stdout := newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "test-token",
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
		t.Fatalf("schema version = %s, want %s", got.SchemaVersion, report.CredentialReportSchemaVersion)
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
			configPath := writeTestConfig(t, fmt.Sprintf(`
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
			root, stdout := newTestCLI(t)
			args := []string{test.command, "--config", configPath, "--rule", "analysis-token", "--no-color"}
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

func TestValidateCommandInputAndOutput(t *testing.T) {
	for _, tc := range []struct {
		name, secret  string
		stdin, simple bool
	}{
		{"stdin JSONL", "from-stdin", true, false},
		{"argument simple", "simple-secret", false, true},
		{"JSON stdin is a secret", `{"type":"authorized_user","client_id":"fake.apps.googleusercontent.com","client_secret":"fake-secret","refresh_token":"fake-refresh"}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "test-token"
regex = 'unused'
validate = '''
finding.secret == %q ? {"result":"valid", "reason":"Authenticated", "metadata":{"owner":"alice"}} : {"result":"invalid"}
'''
`, tc.secret))
			root, output := newTestCLI(t)
			args := []string{"validate", "--config", path, "--rule", "test-token", "--no-color"}
			if tc.stdin {
				root.SetIn(strings.NewReader(tc.secret + "\n"))
			} else {
				args = append(args, tc.secret)
			}
			if tc.simple {
				args = append(args, "--simple")
			} else {
				args = append(args, "--jsonl")
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			require.NotContains(t, output.String(), tc.secret)
			if tc.simple {
				require.Equal(t, "VALID\n", output.String())
			} else {
				var result report.CredentialReport
				require.NoError(t, json.Unmarshal(output.Bytes(), &result))
				require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
			}
		})
	}
}

func TestValidateCommandCompositeCredential(t *testing.T) {
	configPath := writeTestConfig(t, `
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

	root, stdout := newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "account-secret",
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
	configPath := writeTestConfig(t, `
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
			root, stdout := newTestCLI(t)
			args := []string{
				"validate",
				"--config", configPath,
				"--rule", "primary",
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

	root, _ := newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "primary",
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
	configPath := writeTestConfig(t, `
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

	root, stdout := newTestCLI(t)
	root.SetIn(strings.NewReader("secret-primary\n"))
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "client-secret",
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

func TestValidateCommandRequiresReferencedNamedCaptures(t *testing.T) {
	configPath := writeTestConfig(t, `
[[rules]]
id = "capture-dependent"
regex = '''(?P<tenant>[a-z]+)-(?P<id>[a-z]+)-(?P<credential>secret-[a-z]+)'''
secretGroup = 3
validate = '''
finding.captures.tenant == "acme" ? {"result": "valid"} : {"result": "invalid"}
'''
`)

	root, stdout := newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "capture-dependent",
		"secret-value",
	})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "missing required capture(s)") || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("error = %v, want missing tenant capture", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}

	root, stdout = newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "capture-dependent",
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

	configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "limited-token"
regex = '''(limited-token)'''
validate = '''
let r1 = http.get(%q, {});
let r2 = http.get(%q, {});
{"result": "valid", "statuses": [r1.status, r2.status]}
'''
`, server.URL+"/first", server.URL+"/second"))

	root, stdout := newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "limited-token",
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
	configPath := writeTestConfig(t, `
[[rules]]
id = "reported-token"
regex = '''(reported-token)'''
validate = '''{"result": "invalid", "reason": "Unauthorized"}'''
`)
	reportPath := filepath.Join(t.TempDir(), "credential.jsonl")

	root, stdout := newTestCLI(t)
	root.SetArgs([]string{
		"validate",
		"--config", configPath,
		"--rule", "reported-token",
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
	configPath := writeTestConfig(t, `
[[rules]]
id = "simple"
regex = '''(simple)'''
validate = '''{"result": "valid"}'''
analyze = '''{"capabilities": ["read"]}'''
revoke = '''{"result": "revoked"}'''
`)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing rule",
			args: []string{"validate", "--config", configPath, "secret"},
			want: "--rule is required",
		},
		{
			name: "missing secret",
			args: []string{"validate", "--config", configPath, "--rule", "simple"},
			want: "secret argument or piped credential is required",
		},
		{
			name: "extra component",
			args: []string{"validate", "--config", configPath, "--rule", "simple", "--component", "other=value", "secret"},
			want: "not declared",
		},
		{
			name: "duplicate capture",
			args: []string{"validate", "--config", configPath, "--rule", "simple", "--capture", "name=one", "--capture", "name=two", "secret"},
			want: "supplied more than once",
		},
		{
			name: "simple JSONL report",
			args: []string{"validate", "--config", configPath, "--rule", "simple", "--simple", "--jsonl", "secret"},
			want: "--simple cannot be combined",
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

	for _, command := range []string{"validate", "analyze", "revoke"} {
		for _, test := range tests {
			t.Run(command+"/"+test.name, func(t *testing.T) {
				root, _ := newTestCLI(t)
				root.SetArgs(append([]string{command}, test.args[1:]...))
				err := root.Execute()
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want substring %q", err, test.want)
				}
			})
		}
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
	err := unknownCredentialRuleError(cfg, "github", credentialValidation)
	if err == nil || !strings.Contains(err.Error(), "github-pat") || !strings.Contains(err.Error(), "github-oauth") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), "github-unvalidated") {
		t.Fatalf("error suggests an unvalidated rule: %v", err)
	}
}

const credentialRequirementsConfig = `
[[rules]]
id = "component"
regex = '''(unused-component-regex)'''
skipReport = true

[[rules]]
id = "validation-only"
regex = '''(unused-regex)'''
validate = '''{"result": "valid"}'''

[[rules]]
id = "analysis-token"
regex = '''(unused-regex)'''
components = [{ id = "component" }]
validate = '''
finding.secret == "primary-secret" &&
components.component.secret == "component-secret" &&
finding.captures.tenant == "tenant-value" ? {
  "result": "valid",
  "analysis": {"owner": "fixture-owner"}
} : {"result": "invalid"}
'''
analyze = '''
{
  "identity": {"username": validation.analysis.owner},
  "capabilities": ["read"],
  "metadata": {
    "secret": finding.secret,
    "component": components.component.secret,
    "tenant": finding.captures.tenant,
    "scope": finding.captures.scope,
    "region": components.component.captures.region
  }
}
'''
`

func TestCredentialCommandsCaptureRequirements(t *testing.T) {
	configPath := writeTestConfig(t, credentialRequirementsConfig)
	for _, test := range []struct {
		name      string
		command   string
		captures  []string
		wantError string
	}{
		{name: "validate needs only validation captures", command: "validate"},
		{name: "analyze requires primary capture", command: "analyze", wantError: "scope"},
		{name: "analyze requires component capture", command: "analyze", captures: []string{"--capture", "scope=scope-value"}, wantError: "region"},
		{name: "analyze complete input", command: "analyze", captures: []string{"--capture", "scope=scope-value", "--capture", "component:region=region-value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			root.SetIn(strings.NewReader("primary-secret\n"))
			args := []string{test.command, "--config", configPath, "--rule", "analysis-token",
				"--component", "component=component-secret", "--capture", "tenant=tenant-value", "--jsonl"}
			root.SetArgs(append(args, test.captures...))
			err := root.Execute()
			if test.wantError != "" {
				require.ErrorContains(t, err, "missing required capture(s)")
				require.ErrorContains(t, err, test.wantError)
				require.Empty(t, stdout.String())
				return
			}
			require.NoError(t, err)
			var result report.CredentialReport
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, report.CredentialReportSchemaVersion, result.SchemaVersion)
			require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
			require.Len(t, result.ComponentSets, 1)
			require.Equal(t, report.ValidationStatusValid, result.ComponentSets[0].Analysis.Status)
			require.Equal(t, "component", result.ComponentSets[0].Components[0].RuleID)
			if test.command == "analyze" {
				require.NotNil(t, result.Analysis.Identity)
				require.Equal(t, "fixture-owner", result.Analysis.Identity.Username)
				for _, field := range []string{"secret", "component", "tenant", "scope", "region"} {
					require.Equal(t, "[redacted]", result.Analysis.Metadata[field], field)
				}
			} else {
				require.Nil(t, result.Analysis.Identity)
				require.Empty(t, result.Analysis.Metadata)
			}
			for _, value := range []string{"primary-secret", "component-secret", "tenant-value", "scope-value", "region-value"} {
				require.NotContains(t, stdout.String(), value)
			}
		})
	}
}

func TestAnalyzeCommandRequiresAnalysisRule(t *testing.T) {
	configPath := writeTestConfig(t, credentialRequirementsConfig)
	for _, test := range []struct {
		ruleID string
		want   string
	}{
		{ruleID: "validation-only", want: "does not define analysis"},
		{ruleID: "component", want: "does not define analysis"},
		{ruleID: "token", want: "matching rules with analysis: analysis-token"},
		{ruleID: "validation", want: "use config show ids --analysis to see supported rules"},
	} {
		t.Run(test.ruleID, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			root.SetArgs([]string{"analyze", "--config", configPath, "--rule", test.ruleID, "primary-secret"})
			require.ErrorContains(t, root.Execute(), test.want)
			require.Empty(t, stdout.String())
		})
	}
}

func TestAnalyzeCommandSharesRequestBudgetAcrossStages(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "limited-token"
regex = '''(unused-regex)'''
validate = '''
let response = http.get(%q, {});
{"result": "valid"}
'''
analyze = '''
let response = http.get(%q, {});
{"capabilities": ["read"]}
'''
`, server.URL+"/validate", server.URL+"/analyze"))
	for _, limit := range []int{1, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			requests.Store(0)
			root, stdout := newTestCLI(t)
			root.SetArgs([]string{"analyze", "--config", configPath, "--rule", "limited-token",
				"--provider-max-requests", fmt.Sprint(limit), "--jsonl", "fixture-secret"})
			require.NoError(t, root.Execute())
			var result report.CredentialReport
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, report.ValidationStatusValid, result.Analysis.Status)
			require.EqualValues(t, limit, requests.Load())
			if limit == 1 {
				require.Empty(t, result.Analysis.Capabilities)
				require.Equal(t, report.SeverityUnknown, result.Analysis.Severity)
				require.NotEmpty(t, result.Analysis.Reason)
			} else {
				require.Equal(t, report.SeverityMedium, result.Analysis.Severity)
			}
		})
	}
}

func TestRevokeCommandLookupThenDelete(t *testing.T) {
	for _, test := range []struct {
		name, extraction, body string
		lookupStatus           int
		wantDelete             bool
	}{
		{"json", `lookup.json.id ?? ""`, `{"id":"internal-id"}`, 200, true},
		{"regex", `findMatch(lookup.body, "internal-[a-z]+")`, `token_id=internal-id`, 200, true},
		{"header", `lookup.headers["x-token-id"] ?? ""`, `{}`, 200, true},
		{"lookup failed", `lookup.json.id ?? ""`, `{"id":"internal-id"}`, 403, false},
		{"missing ID", `lookup.json.id ?? ""`, `{}`, 200, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var lookups, deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer primary-secret", r.Header.Get("Authorization"))
				switch r.Method + " " + r.URL.Path {
				case "GET /self":
					lookups.Add(1)
					w.Header().Set("X-Token-ID", "internal-id")
					w.WriteHeader(test.lookupStatus)
					fmt.Fprint(w, test.body)
				case "DELETE /tokens/internal-id":
					assert.EqualValues(t, 1, lookups.Load())
					deletes.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer server.Close()
			configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "test-token"
regex = '''(does-not-match-the-supplied-secret)'''
# Direct revocation must not compile or execute these stages.
validate = '''invalid syntax ???'''
analyze = '''invalid syntax ???'''
revoke = '''
let headers = {"Authorization": "Bearer " + finding.secret};
let lookup = http.get(%q + "/self", headers);
lookup.status != 200 ? revoke.unknown(lookup) : (
  let id = %s;
  id == "" ? {"result": "unknown", "reason": "No matching token ID"} : (
    let deleted = http.delete(%q + "/tokens/" + id, headers);
    deleted.status == 204 ? {
      "result": "revoked",
      "reason": "Removed " + finding.secret,
      "metadata": {"echo": finding.secret}
    } : revoke.unknown(deleted)
  )
)
'''
`, server.URL, test.extraction, server.URL))
			root, stdout := newTestCLI(t)
			root.SetIn(strings.NewReader("primary-secret\n"))
			root.SetArgs([]string{"revoke", "--config", configPath, "--rule", "test-token", "--jsonl"})
			require.NoError(t, root.Execute())
			require.EqualValues(t, 1, lookups.Load())
			require.Equal(t, test.wantDelete, deletes.Load() == 1)
			var result report.CredentialReport
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, report.SchemaVersion, result.SchemaVersion)
			if test.wantDelete {
				require.Equal(t, report.ValidationStatusRevoked, result.Analysis.Status)
				require.Equal(t, "Removed [redacted]", result.Analysis.StatusReason)
				require.Equal(t, "[redacted]", result.Analysis.StatusMetadata["echo"])
			} else {
				require.Equal(t, report.ValidationStatusUnknown, result.Analysis.Status)
			}
			require.NotContains(t, stdout.String(), "primary-secret")
			require.Equal(t, 1, strings.Count(stdout.String(), "\n"))
		})
	}
}

func TestRevokeCommandMultipartAndCaptures(t *testing.T) {
	configPath := writeTestConfig(t, `
[[rules]]
id = "account"
regex = '''(?P<account>unused-account)'''

[[rules]]
id = "token"
regex = '''(?P<token>unused-regex)'''
components = [{ id = "account" }]
revoke = '''
finding.captures.token == finding.secret &&
finding.captures.region == "region-value" &&
components.account.captures.account == components.account.secret &&
components.account.captures.tenant == "tenant-value" ? {
  "result": "revoked",
  "metadata": {"component": components.account.secret, "region": finding.captures.region, "tenant": components.account.captures.tenant}
} : {"result": "error"}
'''
`)
	for _, test := range []struct {
		name      string
		flags     []string
		wantError string
	}{
		{"missing captures", []string{"--component", "account=account-secret"}, "missing required capture(s)"},
		{"missing component", []string{"--capture", "region=region-value"}, "missing required component"},
		{"complete", []string{"--component", "account=account-secret", "--capture", "region=region-value", "--capture", "account:tenant=tenant-value"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			args := []string{"revoke", "--config", configPath, "--rule", "token", "--jsonl", "primary-secret"}
			root.SetArgs(append(args, test.flags...))
			err := root.Execute()
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				require.Empty(t, stdout.String())
				return
			}
			require.NoError(t, err)
			var result report.CredentialReport
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
			require.Equal(t, report.ValidationStatusRevoked, result.Analysis.Status)
			require.Len(t, result.ComponentSets, 1)
			require.Equal(t, report.ValidationStatusRevoked, result.ComponentSets[0].Analysis.Status)
			for _, field := range []string{"component", "region", "tenant"} {
				require.Equal(t, "[redacted]", result.Analysis.StatusMetadata[field])
			}
		})
	}
}

func TestRevokeCommandOutputFormats(t *testing.T) {
	configPath := writeTestConfig(t, `[[rules]]
id = "token"
regex = '''unused'''
revoke = '''{"result": "revoked", "reason": "Confirmed removal"}'''
`)
	for _, simple := range []bool{false, true} {
		t.Run(fmt.Sprint(simple), func(t *testing.T) {
			root, stdout := newTestCLI(t)
			args := []string{"revoke", "--config", configPath, "--rule", "token", "--no-color", "primary-secret"}
			if simple {
				args = append(args, "--simple")
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			if simple {
				require.Equal(t, "REVOKED\n", stdout.String())
			} else {
				require.Contains(t, stdout.String(), "Confirmed removal")
			}
		})
	}
}

func TestOnlyRevokeCommandExecutesRevocation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "token"
regex = '''(primary-secret)'''
validate = '''{"result": "valid"}'''
analyze = '''{"capabilities": ["read"]}'''
revoke = '''let response = http.delete(%q, {}); {"result": "revoked"}'''
`, server.URL))
	for _, args := range [][]string{
		{"stdin", "--no-banner", "--exit-code", "0"},
		{"stdin", "--no-banner", "--exit-code", "0", "--no-analysis"},
		{"stdin", "--no-banner", "--exit-code", "0", "--offline"},
		{"validate", "--rule", "token"},
		{"analyze", "--rule", "token"},
		{"config", "check"},
		{"config", "show"},
		{"config", "show", "ids", "--revocation"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root, stdout := newTestCLI(t)
			root.SetIn(strings.NewReader("primary-secret\n"))
			root.SetArgs(append([]string{"--config", configPath}, args...))
			require.NoError(t, root.Execute())
			require.NotEmpty(t, stdout.String())
			require.Zero(t, requests.Load())
		})
	}
	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"revoke", "--config", configPath, "--rule", "token", "--simple", "--no-color", "primary-secret"})
	require.NoError(t, root.Execute())
	require.EqualValues(t, 1, requests.Load())
	require.Equal(t, "REVOKED\n", stdout.String())
}

func TestBuiltinGitHubRevocationReportsSubmission(t *testing.T) {
	const secret = "ghp_fixture-secret"
	var submissions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		submissions.Add(1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/credentials/revoke", r.URL.Path)
		assert.Empty(t, r.Header.Get("Authorization"))
		var payload map[string][]string
		if assert.NoError(t, json.NewDecoder(r.Body).Decode(&payload)) {
			assert.Equal(t, []string{secret}, payload["credentials"])
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	t.Setenv("GITHUB_BASE_URL", server.URL)
	t.Setenv("GITHUB_TOKEN", "must-not-be-used-for-revocation")
	configPath := writeTestConfig(t, "[extend]\nuseDefault = true\n")
	root, stdout := newTestCLI(t)
	root.SetIn(strings.NewReader(secret + "\n"))
	root.SetArgs([]string{"revoke", "--config", configPath, "--rule", "github-pat", "--provider-env-vars", "GITHUB_BASE_URL", "--jsonl"})
	require.NoError(t, root.Execute())
	require.EqualValues(t, 1, submissions.Load())
	var result report.CredentialReport
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
	require.Equal(t, report.ValidationStatusUnknown, result.Analysis.Status)
	require.Equal(t, map[string]any{"submitted": true}, result.Analysis.StatusMetadata)
	require.Contains(t, result.Analysis.StatusReason, "completion is unconfirmed")
	require.NotContains(t, stdout.String(), secret)
}

func TestCredentialProviderDebug(t *testing.T) {
	const secret = `primary+"debug&value`
	const component = "component/debug+value"
	const capture = "capture debug&value"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, secret, r.URL.Query().Get("token"))
		assert.Equal(t, "Bearer "+secret, r.Header.Get("Authorization"))
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "fixture-request-id")
		w.Header().Set("Set-Cookie", "session=provider-session-value")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message":"fixture permission denied","echo":`+string(body)+`}`)
	}))
	defer server.Close()
	requestExpr := fmt.Sprintf(`let r = http.post(%q + "?token=" + strings.urlQueryEscape(finding.secret), {
  "Authorization": "Bearer " + finding.secret,
  "Content-Type": "application/json"
}, toJSON({"token": finding.secret, "component": components.account.secret, "capture": finding.captures.region}));
`, server.URL)
	configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "account"
regex = '''unused'''
[[rules]]
id = "token"
regex = '''unused'''
components = [{id = "account"}]
validate = '''%s validate.unknown(r)'''
analyze = '''{"capabilities": []}'''
revoke = '''%s revoke.unknown(r)'''
`, requestExpr, requestExpr))
	for _, command := range []string{"validate", "analyze", "revoke"} {
		for _, format := range []string{"pretty", "jsonl", "simple"} {
			for _, debug := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/debug=%t", command, format, debug), func(t *testing.T) {
					before := requests.Load()
					root, stdout := newTestCLI(t)
					root.SetIn(strings.NewReader(secret + "\n"))
					args := []string{command, "--config", configPath, "--rule", "token", "--no-color",
						"--component", "account=" + component, "--capture", "region=" + capture}
					if format != "pretty" {
						args = append(args, "--"+format)
					}
					if debug {
						args = append(args, "--provider-debug")
					}
					root.SetArgs(args)
					require.NoError(t, root.Execute())
					require.Equal(t, before+1, requests.Load(), "debug must not add provider requests")
					for _, value := range []string{secret, component, capture, "provider-session-value"} {
						require.NotContains(t, stdout.String(), value)
					}
					if format == "simple" {
						require.Equal(t, "UNKNOWN\n", stdout.String())
						return
					}
					if !debug {
						require.NotContains(t, stdout.String(), "fixture permission denied")
						require.NotContains(t, stdout.String(), "req_method")
					} else {
						require.Contains(t, stdout.String(), "fixture permission denied")
						require.Contains(t, stdout.String(), "fixture-request-id")
						require.Contains(t, stdout.String(), "[redacted]")
					}
					if format == "jsonl" {
						var result report.CredentialReport
						require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
						require.Equal(t, report.ValidationStatusUnknown, result.Analysis.Status)
						require.Equal(t, "HTTP 403", result.Analysis.StatusReason)
						if !debug {
							require.Empty(t, result.Analysis.Debug)
							return
						}
						stage := "validation"
						if command == "revoke" {
							stage = "revocation"
						}
						diagnostics := result.Analysis.Debug[stage].(map[string]any)
						require.Equal(t, "POST", diagnostics["req_method"])
						require.EqualValues(t, 403, diagnostics["resp_status"])
						require.Equal(t, "[redacted]", diagnostics["req_header_authorization"])
						require.Equal(t, "[redacted]", diagnostics["resp_header_set-cookie"])
						require.Equal(t, server.URL+"?token=[redacted]", diagnostics["req_url"])
						require.JSONEq(t, `{"token":"[redacted]","component":"[redacted]","capture":"[redacted]"}`, diagnostics["req_body"].(string))
						require.Equal(t, report.Analysis{Status: result.Analysis.Status, Severity: result.Analysis.Severity}, result.ComponentSets[0].Analysis)
					}
				})
			}
		}
	}
}

func TestAnalyzeProviderDebugIncludesBothStages(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/permissions" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"permission lookup denied"}`)
			return
		}
		fmt.Fprint(w, `{"valid":true}`)
	}))
	defer server.Close()
	configPath := writeTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "token"
regex = '''unused'''
validate = '''let r = http.get(%q + "/validate", {}); {"result":"valid"}'''
analyze = '''let r = http.get(%q + "/permissions", {}); {"reason":"Permission lookup failed"}'''
`, server.URL, server.URL))
	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"analyze", "--config", configPath, "--rule", "token", "--provider-debug", "--jsonl", "fixture-secret"})
	require.NoError(t, root.Execute())
	require.EqualValues(t, 2, requests.Load())
	var result report.CredentialReport
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
	require.EqualValues(t, 200, result.Analysis.Debug["validation"].(map[string]any)["resp_status"])
	diagnostics := result.Analysis.Debug["analysis"].(map[string]any)
	require.EqualValues(t, 403, diagnostics["resp_status"])
	require.Contains(t, diagnostics["resp_body"], "permission lookup denied")
}

func TestGitLabRevocationDebugExplainsForbiddenResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v4/personal_access_tokens/self", r.URL.Path)
		w.Header().Set("X-Request-ID", "gitlab-fixture-trace")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"insufficient_scope","scope":"api"}`)
	}))
	defer server.Close()
	t.Setenv("GITLAB_BASE_URL", server.URL)
	configPath := writeTestConfig(t, "[extend]\nuseDefault = true\n")
	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"revoke", "--config", configPath, "--rule", "gitlab-pat-routable-versioned",
		"--provider-env-vars", "GITLAB_BASE_URL", "--provider-debug", "--no-color", "fixture-gitlab-token"})
	require.NoError(t, root.Execute())
	require.Contains(t, stdout.String(), "HTTP 403")
	require.Contains(t, stdout.String(), "insufficient_scope")
	require.Contains(t, stdout.String(), "gitlab-fixture-trace")
	require.Contains(t, stdout.String(), "DELETE")
	require.NotContains(t, stdout.String(), "fixture-gitlab-token")
}
