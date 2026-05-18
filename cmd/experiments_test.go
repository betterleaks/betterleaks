package cmd

import (
	"strings"
	"testing"
)

func TestValidateExperiments(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantErr   bool
		wantInErr string
	}{
		{"empty", "", false, ""},
		{"only commas and whitespace", " , , ", false, ""},
		{"single unknown", "fake", true, "fake"},
		{"multiple unknown sorted", "zebra,apple", true, "apple, zebra"},
		{"trims whitespace", "  fake  ", true, "fake"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExperiments(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("validateExperiments(%q): expected error, got nil", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateExperiments(%q): unexpected error %v", tc.in, err)
			}
			if err != nil && tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("validateExperiments(%q): error %q missing %q", tc.in, err.Error(), tc.wantInErr)
			}
		})
	}
}

func TestValidateExperimentsKnownEntry(t *testing.T) {
	validExperiments["test-only-flag"] = struct{}{}
	t.Cleanup(func() { delete(validExperiments, "test-only-flag") })

	if err := validateExperiments("test-only-flag"); err != nil {
		t.Errorf("validateExperiments rejected a registered value: %v", err)
	}
	if err := validateExperiments("test-only-flag,nope"); err == nil {
		t.Error("validateExperiments accepted unknown value when mixed with known")
	}
}
