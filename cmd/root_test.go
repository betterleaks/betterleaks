package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestValidateExperiments(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantError string
	}{
		{
			name:  "empty",
			value: "",
		},
		{
			name:  "empty tokens",
			value: " , ",
		},
		{
			name:      "unknown experiment",
			value:     "fake",
			wantError: `unknown experiment "fake"`,
		},
		{
			name:      "validation is no longer experimental",
			value:     "validation",
			wantError: `unknown experiment "validation"`,
		},
		{
			name:      "normalizes whitespace and case",
			value:     " Fake ",
			wantError: `unknown experiment "fake"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExperiments(tt.value)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("validateExperiments(%q) error = %v", tt.value, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateExperiments(%q) error = nil, want %q", tt.value, tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("validateExperiments(%q) error = %q, want substring %q", tt.value, err.Error(), tt.wantError)
			}
		})
	}
}

func TestInvalidExperimentsDoesNotPrintUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	versionSilenceUsage := versionCmd.SilenceUsage
	defer func() {
		versionCmd.SilenceUsage = versionSilenceUsage
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(os.Stdout)
		rootCmd.SetErr(os.Stderr)
	}()

	rootCmd.SetArgs([]string{"version", "--experiments=fewaf", "--no-banner"})
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("rootCmd.Execute() error = nil, want invalid experiment error")
	}
	if !strings.Contains(err.Error(), `unknown experiment "fewaf"`) {
		t.Fatalf("rootCmd.Execute() error = %q, want invalid experiment error", err.Error())
	}
	if strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("stdout contains usage: %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("stderr contains usage: %q", stderr.String())
	}
}
