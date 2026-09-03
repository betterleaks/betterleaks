package validate

import (
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
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

	// An unrecognized status falls back to "unknown".
	if s := parseResultMap(map[string]any{"result": "bogus"}).Status; s != report.ValidationStatusUnknown {
		t.Errorf("unrecognized status should fall back to unknown, got %q", s)
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
