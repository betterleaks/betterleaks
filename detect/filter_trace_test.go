package detect

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/betterleaks/betterleaks/logging"
)

// TestRuleFilterSkipEmitsTrace verifies that when a candidate matches a rule's
// regex but is then dropped by the rule's filter, a trace-level log explains
// the reason instead of the finding silently disappearing (issue #162).
func TestRuleFilterSkipEmitsTrace(t *testing.T) {
	d, err := NewDetectorDefaultConfig()
	if err != nil {
		t.Fatalf("NewDetectorDefaultConfig: %v", err)
	}

	var buf bytes.Buffer
	orig := logging.Logger
	logging.Logger = zerolog.New(&buf).Level(zerolog.TraceLevel)
	t.Cleanup(func() { logging.Logger = orig })

	// "ghp_" + 36 chars matches the github-pat regex, but an all-"a" token has
	// ~0 entropy and is dropped by that rule's `entropy(secret) <= 3.0` filter.
	token := "ghp_" + strings.Repeat("a", 36)
	findings := d.DetectString(`token = "` + token + `"`)
	if len(findings) != 0 {
		t.Fatalf("expected the low-entropy token to be filtered out, got %d finding(s)", len(findings))
	}

	if out := buf.String(); !strings.Contains(out, "dropped by the rule filter") {
		t.Fatalf("expected a trace log explaining the rule-filter skip, got:\n%s", out)
	}
}
