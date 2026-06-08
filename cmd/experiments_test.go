package cmd

import (
	"strings"
	"testing"
)

func TestParseExperimentsIgnoresEmptyEntries(t *testing.T) {
	tests := map[string]string{
		"empty string":       "",
		"whitespace only":    "   ",
		"commas only":        ",, ,",
		"trailing comma gap": " , , ",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseExperiments(raw)
			if err != nil {
				t.Fatalf("parseExperiments(%q) returned unexpected error: %v", raw, err)
			}
			if len(got) != 0 {
				t.Fatalf("parseExperiments(%q) = %v, want empty set", raw, got)
			}
		})
	}
}

func TestParseExperimentsRejectsUnknown(t *testing.T) {
	for _, raw := range []string{"fake", "fake,bogus", "  fake  "} {
		got, err := parseExperiments(raw)
		if err == nil {
			t.Fatalf("parseExperiments(%q) = %v, want error", raw, got)
		}
		if got != nil {
			t.Fatalf("parseExperiments(%q) returned non-nil set on error: %v", raw, got)
		}
		if !strings.Contains(err.Error(), "fake") {
			t.Fatalf("parseExperiments(%q) error %q does not name the offending value", raw, err)
		}
	}
}

func TestParseExperimentsAcceptsKnown(t *testing.T) {
	orig := knownExperiments
	knownExperiments = map[string]struct{}{"alpha": {}, "beta": {}}
	t.Cleanup(func() { knownExperiments = orig })

	got, err := parseExperiments(" alpha , beta ")
	if err != nil {
		t.Fatalf("parseExperiments returned unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parseExperiments enabled %d experiments, want 2", len(got))
	}
	if _, ok := got["alpha"]; !ok {
		t.Fatal("expected experiment \"alpha\" to be enabled")
	}

	_, err = parseExperiments("alpha,gamma")
	if err == nil {
		t.Fatal("expected error when mixing known and unknown experiments")
	}
	if !strings.Contains(err.Error(), "gamma") || !strings.Contains(err.Error(), "alpha, beta") {
		t.Fatalf("error %q should name the unknown value and list valid values", err)
	}
}
