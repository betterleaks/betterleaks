package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialReportRedactsOverlappingSecretsAndMetadataKeys(t *testing.T) {
	got := NewCredentialReport(Finding{
		RuleID: "test",
		Attributes: map[string]string{
			"credential-abcdef": "abcdef abc",
		},
		Validation: Validation{
			Status: ValidationStatusValid,
			Metadata: map[string]any{
				"credential-abcdef": "abcdef abc",
			},
		},
	}, []string{"abc", "abcdef"}, false)

	value, ok := got.Validation.Metadata["credential-[redacted]"]
	if !ok {
		t.Fatalf("sanitized metadata keys = %#v", got.Validation.Metadata)
	}
	if value != "[redacted] [redacted]" {
		t.Fatalf("sanitized metadata value = %#v", value)
	}
	if got.Attributes["credential-[redacted]"] != "[redacted] [redacted]" {
		t.Fatalf("sanitized attributes = %#v", got.Attributes)
	}
}

func TestCredentialReporterWritesText(t *testing.T) {
	result := CredentialReport{
		SchemaVersion: CredentialReportSchemaVersion,
		RuleID:        "test-rule",
		Validation: CredentialValidationReport{
			Status: ValidationStatusValid,
			Reason: "Authenticated",
			Metadata: map[string]any{
				"zeta":  int64(2),
				"alpha": "owner",
			},
			ComponentSets: []CredentialComponentSetReport{{
				Status: ValidationStatusValid,
				Components: []CredentialComponentReport{
					{RuleID: "component"},
					{RuleID: "context", Optional: true},
				},
			}},
		},
	}
	var output bytes.Buffer
	reporter := CredentialReporter{Format: CredentialReportFormatPretty, NoColor: true}
	if err := reporter.Write(&output, result); err != nil {
		t.Fatalf("write text: %v", err)
	}
	want := `
┌─test-rule──○
│
│ validation:
│   status ...... VALID
│   reason ...... Authenticated
│   alpha ....... "owner"
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
		RuleID:     "test-rule",
		Validation: Validation{Status: ValidationStatusValid},
		ComponentSets: []ComponentSet{{
			Validation: Validation{Status: ValidationStatusValid},
			Components: []*ComponentFinding{
				{RuleID: "required-component"},
				{RuleID: "optional-component", Optional: true},
			},
		}},
	}, nil, false)

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
		Validation: CredentialValidationReport{
			Status: ValidationStatusValid,
		},
	}

	var output bytes.Buffer
	reporter := CredentialReporter{Format: CredentialReportFormatJSONL}
	if err := reporter.Write(&output, result); err != nil {
		t.Fatalf("write JSONL: %v", err)
	}
	want := `{"schema_version":1,"rule_id":"test-rule","validation":{"status":"valid"}}` + "\n"
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
