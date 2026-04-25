package cmd

import (
	"testing"

	"github.com/betterleaks/betterleaks/report"
)

func TestParseValidationStatusFilter(t *testing.T) {
	filter, err := parseValidationStatusFilter(" valid,INVALID, none,,unknown ")
	if err != nil {
		t.Fatalf("parseValidationStatusFilter returned error: %v", err)
	}

	for _, status := range []report.ValidationStatus{
		report.ValidationStatusValid,
		report.ValidationStatusInvalid,
		report.ValidationStatusNone,
		report.ValidationStatusUnknown,
	} {
		if _, ok := filter[status]; !ok {
			t.Fatalf("expected filter to include %q", status)
		}
	}
	if _, ok := filter[report.ValidationStatus("")]; ok {
		t.Fatal("expected empty validation status to be ignored")
	}
}

func TestParseValidationStatusFilterRejectsUnknownValue(t *testing.T) {
	if _, err := parseValidationStatusFilter("valid,not-a-status"); err == nil {
		t.Fatal("expected unknown validation status to return an error")
	}
}
