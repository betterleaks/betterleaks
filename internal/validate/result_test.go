package validate

import (
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

func TestBetterStatusPriority(t *testing.T) {
	tests := []struct {
		a, b, want report.ValidationStatus
	}{
		{report.ValidationStatusNone, report.ValidationStatusValid, report.ValidationStatusValid},
		{report.ValidationStatusValid, report.ValidationStatusInvalid, report.ValidationStatusValid},
		{report.ValidationStatusError, report.ValidationStatusInvalid, report.ValidationStatusInvalid},
		{report.ValidationStatusNeedsValidation, report.ValidationStatusRevoked, report.ValidationStatusNeedsValidation},
		{report.ValidationStatusUnknown, report.ValidationStatusNone, report.ValidationStatusUnknown},
	}
	for _, tc := range tests {
		if got := BetterStatus(tc.a, tc.b); got != tc.want {
			t.Errorf("BetterStatus(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
		// Result is independent of argument order.
		if got := BetterStatus(tc.b, tc.a); got != tc.want {
			t.Errorf("BetterStatus(%q, %q) = %q, want %q", tc.b, tc.a, got, tc.want)
		}
	}
}

func TestParseResultMapNormalizesStatus(t *testing.T) {
	got := parseResultMap(map[string]any{
		"result":   "VALID",
		"reason":   "ok",
		"extra":    "m",
		"analysis": map[string]any{"owner": "user-1"},
	})
	if got.Status != report.ValidationStatusValid {
		t.Errorf("status: got %q want valid", got.Status)
	}
	if got.Reason != "ok" {
		t.Errorf("reason: got %q want ok", got.Reason)
	}
	if got.Metadata["extra"] != "m" {
		t.Errorf("metadata not captured: %v", got.Metadata)
	}
	if _, exists := got.Metadata["analysis"]; exists {
		t.Errorf("analysis input leaked into metadata: %v", got.Metadata)
	}
	if got.Analysis["owner"] != "user-1" {
		t.Errorf("analysis input not captured: %v", got.Analysis)
	}

}

func TestParseResultRejectsMalformedResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		value  any
		reason string
	}{
		{"empty map", map[string]any{}, "validation result is required"},
		{"missing result", map[string]any{"foo": "bar"}, "validation result is required"},
		{"number", map[string]any{"result": 123}, "validation result must be a string"},
		{"null", map[string]any{"result": nil}, "validation result must be a string"},
		{"empty status", map[string]any{"result": ""}, "validation result must be one of:"},
		{"unknown status", map[string]any{"result": "bogus"}, "validation result must be one of:"},
		{"number reason", map[string]any{"result": "valid", "reason": 123}, "validation reason must be a string"},
		{"null reason", map[string]any{"result": "valid", "reason": nil}, "validation reason must be a string"},
		{"interface keys", map[any]any{"result": false}, "validation result must be a string"},
		{"non-map", "valid", "expression returned unexpected type:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ParseResult(test.value)
			require.Equal(t, report.ValidationStatusError, got.Status)
			require.Contains(t, got.Reason, test.reason)
		})
	}
}

func TestParseResultAcceptsKnownStatuses(t *testing.T) {
	for _, status := range []report.ValidationStatus{
		report.ValidationStatusValid, report.ValidationStatusNeedsValidation,
		report.ValidationStatusInvalid, report.ValidationStatusRevoked,
		report.ValidationStatusUnknown, report.ValidationStatusError,
	} {
		for _, text := range []string{string(status), strings.ToUpper(string(status))} {
			got := ParseResult(map[string]any{"result": text, "reason": "provider explanation", "public": true})
			require.Equal(t, status, got.Status)
			require.Equal(t, "provider explanation", got.Reason)
			require.Equal(t, true, got.Metadata["public"])
		}
	}
}

func TestParseResultMapRejectsInvalidAnalysisInput(t *testing.T) {
	got := parseResultMap(map[string]any{"result": "valid", "analysis": []string{"read"}})
	if got.Status != report.ValidationStatusError {
		t.Fatalf("status: got %q want error", got.Status)
	}
	if got.Reason != "validation analysis must be an object, got []string" {
		t.Fatalf("reason: got %q", got.Reason)
	}
}
