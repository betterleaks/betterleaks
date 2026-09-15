package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

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
	configPath := writeValidateTestConfig(t, credentialRequirementsConfig)
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
			root, stdout := newValidateTestRoot(t)
			root.SetIn(strings.NewReader("primary-secret\n"))
			args := []string{test.command, "--config", configPath, "--rule-id", "analysis-token",
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
	configPath := writeValidateTestConfig(t, credentialRequirementsConfig)
	for _, test := range []struct {
		ruleID string
		want   string
	}{
		{ruleID: "validation-only", want: "does not define analysis"},
		{ruleID: "component", want: "does not define validation"},
		{ruleID: "token", want: "matching rules with analysis: analysis-token"},
		{ruleID: "validation", want: "use config show ids --analysis to see supported rules"},
	} {
		t.Run(test.ruleID, func(t *testing.T) {
			root, stdout := newValidateTestRoot(t)
			root.SetArgs([]string{"analyze", "--config", configPath, "--rule-id", test.ruleID, "primary-secret"})
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
	configPath := writeValidateTestConfig(t, fmt.Sprintf(`
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
			root, stdout := newValidateTestRoot(t)
			root.SetArgs([]string{"analyze", "--config", configPath, "--rule-id", "limited-token",
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
