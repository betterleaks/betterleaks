package cmd

import (
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
