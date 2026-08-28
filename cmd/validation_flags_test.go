package cmd

import (
	"math"
	"testing"

	"github.com/spf13/cobra"
)

func TestParseValidationRuleRPS(t *testing.T) {
	got, err := parseValidationRuleRPS([]string{"github-pat=2", "gcp-service-account=0.5"})
	if err != nil {
		t.Fatalf("parseValidationRuleRPS: %v", err)
	}
	if got["github-pat"] != 2 {
		t.Fatalf("github rate = %v, want 2", got["github-pat"])
	}
	if got["gcp-service-account"] != 0.5 {
		t.Fatalf("gcp rate = %v, want 0.5", got["gcp-service-account"])
	}
}

func TestParseValidationRuleRPSRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{
		"github-pat",
		"=1",
		"github-pat=0",
		"github-pat=-1",
		"github-pat=not-a-number",
		"github-pat=1,github-pat=2",
	} {
		if _, err := parseValidationRuleRPS([]string{value}); err == nil {
			t.Fatalf("parseValidationRuleRPS(%q) returned no error", value)
		}
	}
	if _, err := parseValidationRuleRPS([]string{"github-pat=1", "github-pat=2"}); err == nil {
		t.Fatal("duplicate rule rate returned no error")
	}
}

func TestValidateValidationRPS(t *testing.T) {
	for _, value := range []float64{0, 0.5, 10} {
		if err := validateValidationRPS(value); err != nil {
			t.Fatalf("validateValidationRPS(%v): %v", value, err)
		}
	}
	for _, value := range []float64{-1, math.NaN(), math.Inf(1)} {
		if err := validateValidationRPS(value); err == nil {
			t.Fatalf("validateValidationRPS(%v) returned no error", value)
		}
	}
}

func TestGetValidationMaxRequests(t *testing.T) {
	newCommand := func(args ...string) *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().Int("validation-max-requests", 0, "")
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		return cmd
	}

	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "default", want: 0},
		{name: "configured", args: []string{"--validation-max-requests=10"}, want: 10},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := getValidationMaxRequests(newCommand(test.args...))
			if err != nil {
				t.Fatalf("getValidationMaxRequests: %v", err)
			}
			if got != test.want {
				t.Fatalf("max requests = %d, want %d", got, test.want)
			}
		})
	}

	if _, err := getValidationMaxRequests(newCommand("--validation-max-requests=-1")); err == nil {
		t.Fatal("negative maximum returned no error")
	}
}
