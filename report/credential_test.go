package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
)

func TestCredentialReportRedactsEncodedDebugValues(t *testing.T) {
	const secret = "fixture+\"secret/&<> with\nnewline"
	encodedJSON, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	var unescapedJSON bytes.Buffer
	encoder := json.NewEncoder(&unescapedJSON)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(secret); err != nil {
		t.Fatal(err)
	}
	jsonWithoutHTMLEscaping := strings.TrimSuffix(unescapedJSON.String(), "\n")
	for name, value := range map[string]string{
		"raw":   secret,
		"query": url.QueryEscape(secret), "path": url.PathEscape(secret),
		"json":                       string(encodedJSON[1 : len(encodedJSON)-1]),
		"json without HTML escaping": jsonWithoutHTMLEscaping[1 : len(jsonWithoutHTMLEscaping)-1],
		"base64":                     base64.StdEncoding.EncodeToString([]byte(secret)),
		"raw base64":                 base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"url base64":                 base64.URLEncoding.EncodeToString([]byte(secret)),
		"raw url base64":             base64.RawURLEncoding.EncodeToString([]byte(secret)),
	} {
		t.Run(name, func(t *testing.T) {
			finding := Finding{Analysis: Analysis{Debug: map[string]any{"revocation": map[string]any{"resp_body": "message: " + value}}}}
			result := NewCredentialReport(finding, []string{secret})
			got := result.Analysis.Debug["revocation"].(map[string]any)["resp_body"]
			if got != "message: [redacted]" {
				t.Fatalf("debug body = %q", got)
			}
			if finding.Analysis.Debug["revocation"].(map[string]any)["resp_body"] != "message: "+value {
				t.Fatal("sanitizing debug mutated the input finding")
			}
		})
	}
}

func TestCredentialReportRedactsOverlappingSecretsAndMetadataKeys(t *testing.T) {
	got := NewCredentialReport(Finding{
		RuleID: "test",
		Attributes: map[string]string{
			"credential-abcdef": "abcdef abc",
		},
		Analysis: Analysis{
			Status: ValidationStatusValid,
			Metadata: map[string]any{
				"credential-abcdef": "abcdef abc",
			},
		},
	}, []string{"abc", "abcdef"})

	value, ok := got.Analysis.Metadata["credential-[redacted]"]
	if !ok {
		t.Fatalf("sanitized metadata keys = %#v", got.Analysis.Metadata)
	}
	if value != "[redacted] [redacted]" {
		t.Fatalf("sanitized metadata value = %#v", value)
	}
	if got.Attributes["credential-[redacted]"] != "[redacted] [redacted]" {
		t.Fatalf("sanitized attributes = %#v", got.Attributes)
	}
}

func TestCredentialReportOmitsInternalAttributes(t *testing.T) {
	got := NewCredentialReport(Finding{
		RuleID: "test",
		Attributes: map[string]string{
			sources.AttrPath:            "secrets.txt",
			sources.AttrFSFirstFragment: "true",
		},
	}, nil)

	if _, ok := got.Attributes[sources.AttrFSFirstFragment]; ok {
		t.Fatalf("internal attribute included in credential report: %#v", got.Attributes)
	}
	if len(got.Attributes) != 0 {
		t.Fatalf("report attributes = %#v", got.Attributes)
	}
}

func TestCredentialReportAnalysis(t *testing.T) {
	analysis := Analysis{
		Status:   ValidationStatusValid,
		Severity: SeverityMedium,
		Identity: &AnalysisIdentity{Username: "owner-secret-value"},
		Metadata: map[string]any{"credential": "secret-value"},
	}
	finding := Finding{
		RuleID:   "demo",
		Analysis: analysis,
		ComponentSets: []ComponentSet{{
			Analysis:   analysis,
			Components: []ComponentFinding{{RuleID: "part"}},
		}},
	}
	result := NewCredentialReport(finding, []string{"secret-value"})
	if result.Analysis.Identity.Username != "owner-[redacted]" ||
		result.ComponentSets[0].Analysis.Identity.Username != "owner-[redacted]" {
		t.Fatalf("analysis was not sanitized: %#v", result)
	}
	if analysis.Identity.Username != "owner-secret-value" {
		t.Fatal("report construction mutated the original analysis")
	}
	for _, format := range []CredentialReportFormat{CredentialReportFormatJSONL, CredentialReportFormatPretty} {
		t.Run(string(format), func(t *testing.T) {
			var output bytes.Buffer
			if err := (CredentialReporter{Format: format, NoColor: true}).Write(&output, result); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output.String(), "secret-value") ||
				!strings.Contains(output.String(), "owner-[redacted]") ||
				!strings.Contains(output.String(), "analysis") {
				t.Fatalf("unexpected analysis output: %s", &output)
			}
		})
	}
}

func TestCredentialReportOmitsEmptyValidationMetadata(t *testing.T) {
	got := NewCredentialReport(Finding{
		RuleID: "test",
		Analysis: Analysis{
			Status: ValidationStatusValid,
			Metadata: map[string]any{
				"empty": "",
				"nil":   nil,
				"false": false,
				"zero":  0,
			},
		},
	}, nil)

	if _, ok := got.Analysis.Metadata["empty"]; ok {
		t.Fatalf("empty string included in metadata: %#v", got.Analysis.Metadata)
	}
	if _, ok := got.Analysis.Metadata["nil"]; ok {
		t.Fatalf("nil included in metadata: %#v", got.Analysis.Metadata)
	}
	if got.Analysis.Metadata["false"] != false || got.Analysis.Metadata["zero"] != 0 {
		t.Fatalf("meaningful zero values omitted from metadata: %#v", got.Analysis.Metadata)
	}
}

func TestCredentialReporterWritesText(t *testing.T) {
	result := CredentialReport{
		SchemaVersion: CredentialReportSchemaVersion,
		RuleID:        "test-rule",
		Analysis: Analysis{
			Status: ValidationStatusValid,
			Reason: "Authenticated",
			Metadata: map[string]any{
				"zeta":  int64(2),
				"alpha": "owner",
			},
		},
		ComponentSets: []CredentialComponentSetReport{{
			Analysis: Analysis{Status: ValidationStatusValid},
			Components: []CredentialComponentReport{
				{RuleID: "component"},
				{RuleID: "context", Optional: true},
			},
		}},
	}
	var output bytes.Buffer
	reporter := CredentialReporter{Format: CredentialReportFormatPretty, NoColor: true}
	if err := reporter.Write(&output, result); err != nil {
		t.Fatalf("write text: %v", err)
	}
	want := `
┌─test-rule──○
│
│
│ analysis:
│   alpha ....... "owner"
│   reason ...... Authenticated
│   status ...... VALID
│   zeta ........ 2
│
│ components:
│   ✓  component, context (optional)
└○

`
	if output.String() != want {
		t.Fatalf("text output:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestCredentialReportUsesComponentSchema(t *testing.T) {
	result := NewCredentialReport(Finding{
		RuleID:   "test-rule",
		Analysis: Analysis{Status: ValidationStatusValid},
		ComponentSets: []ComponentSet{{
			Analysis: Analysis{Status: ValidationStatusValid},
			Components: []ComponentFinding{
				{RuleID: "required-component"},
				{RuleID: "optional-component", Optional: true},
			},
		}},
	}, nil)

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	encoded := string(data)
	if !strings.Contains(encoded, `"component_sets"`) || !strings.Contains(encoded, `"optional":true`) {
		t.Fatalf("component schema missing from %s", encoded)
	}
	if strings.Contains(encoded, "required_sets") || strings.Contains(encoded, "required_components") {
		t.Fatalf("legacy required schema present in %s", encoded)
	}
}

func TestCredentialReporterWritesComponentList(t *testing.T) {
	result := CredentialRuleList{
		SchemaVersion: CredentialReportSchemaVersion,
		Rules: []CredentialRuleSummary{{
			RuleID:   "multipart-rule",
			Captures: []string{"account", "tenant"},
			Components: []CredentialComponentReport{
				{RuleID: "account-id"},
				{RuleID: "region", Optional: true},
			},
		}},
	}

	var output bytes.Buffer
	reporter := CredentialReporter{Format: CredentialReportFormatPretty, NoColor: true}
	if err := reporter.WriteRuleList(&output, result); err != nil {
		t.Fatalf("write rule list: %v", err)
	}
	want := "RULE ID         COMPONENTS                     CAPTURES\n" +
		"multipart-rule  account-id, region (optional)  account, tenant\n"
	if output.String() != want {
		t.Fatalf("rule list output = %q, want %q", output.String(), want)
	}
}

func TestCredentialReporterWritesJSONL(t *testing.T) {
	result := CredentialReport{
		SchemaVersion: CredentialReportSchemaVersion,
		RuleID:        "test-rule",
		Analysis: Analysis{
			Status: ValidationStatusValid,
		},
	}

	var output bytes.Buffer
	reporter := CredentialReporter{Format: CredentialReportFormatJSONL}
	if err := reporter.Write(&output, result); err != nil {
		t.Fatalf("write JSONL: %v", err)
	}
	want := `{"schema_version":2,"rule_id":"test-rule","analysis":{"status":"valid"}}` + "\n"
	if output.String() != want {
		t.Fatalf("JSONL output = %q, want %q", output.String(), want)
	}
}

func TestResolveCredentialReportFormat(t *testing.T) {
	tests := []struct {
		input string
		want  CredentialReportFormat
	}{
		{input: "", want: CredentialReportFormatPretty},
		{input: "pretty", want: CredentialReportFormatPretty},
		{input: " JSONL ", want: CredentialReportFormatJSONL},
	}
	for _, test := range tests {
		got, err := ResolveCredentialReportFormat(test.input)
		if err != nil {
			t.Fatalf("ResolveCredentialReportFormat(%q): %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("ResolveCredentialReportFormat(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	if _, err := ResolveCredentialReportFormat("json"); err == nil {
		t.Fatal("legacy json format was accepted")
	}
}
