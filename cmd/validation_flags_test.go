package cmd

import (
	"math"
	"reflect"
	"testing"

	"github.com/betterleaks/betterleaks/report"
)

func TestParseValidationStatuses(t *testing.T) {
	got, err := parseValidationStatuses(" valid, NONE,needs_validation ")
	if err != nil {
		t.Fatalf("parseValidationStatuses: %v", err)
	}
	want := []report.ValidationStatus{
		report.ValidationStatusValid,
		report.ValidationStatusNone,
		report.ValidationStatusNeedsValidation,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statuses = %v, want %v", got, want)
	}
	if _, err := parseValidationStatuses("valid,surprising"); err == nil {
		t.Fatal("invalid status returned no error")
	}
}

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

func TestValidationRuntimeFlagsRejectNegativeMaxRequests(t *testing.T) {
	flags := ValidationRuntimeFlags{ValidationMaxRequests: -1}
	if err := flags.Validate(); err == nil {
		t.Fatal("negative maximum returned no error")
	}
}
