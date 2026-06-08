package report

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestValidationStatusJSONIsPlainString guards the wire contract: the typed
// ValidationStatus must still serialize as the same plain JSON string as the
// previous string field, so existing report consumers are unaffected.
func TestValidationStatusJSONIsPlainString(t *testing.T) {
	b, err := json.Marshal(Finding{RuleID: "x", ValidationStatus: ValidationStatusValid})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"ValidationStatus":"valid"`) {
		t.Fatalf("expected ValidationStatus to serialize as \"valid\", got: %s", b)
	}

	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.ValidationStatus != ValidationStatusValid {
		t.Fatalf("round-trip mismatch: got %q", back.ValidationStatus)
	}
}

func TestValidationStatusNoneOmitted(t *testing.T) {
	b, _ := json.Marshal(Finding{RuleID: "x"})
	if strings.Contains(string(b), "ValidationStatus") {
		t.Fatalf("empty ValidationStatus should be omitted from JSON, got: %s", b)
	}
}
