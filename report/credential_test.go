package report

import (
	"bytes"
	"testing"
)

func TestCredentialReportRedactsOverlappingSecretsAndMetadataKeys(t *testing.T) {
	got := NewCredentialReport(Finding{
		RuleID:           "test",
		ValidationStatus: ValidationStatusValid,
		ValidationMeta: map[string]any{
			"credential-abcdef": "abcdef abc",
		},
	}, []string{"abc", "abcdef"}, false)

	value, ok := got.Validation.Metadata["credential-[redacted]"]
	if !ok {
		t.Fatalf("sanitized metadata keys = %#v", got.Validation.Metadata)
	}
	if value != "[redacted] [redacted]" {
		t.Fatalf("sanitized metadata value = %#v", value)
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
			RequiredSets: []CredentialRequiredSetReport{{
				Status:     ValidationStatusValid,
				Components: []string{"component"},
			}},
		},
	}
	var output bytes.Buffer
	reporter := CredentialReporter{Format: CredentialReportFormatText, NoColor: true}
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
│   ✓  component
└○

`
	if output.String() != want {
		t.Fatalf("text output:\n%s\nwant:\n%s", output.String(), want)
	}
}
