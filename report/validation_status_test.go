package report

import "testing"

func TestParseValidationStatus(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want ValidationStatus
		ok   bool
	}{
		{name: "valid", in: "valid", want: ValidationStatusValid, ok: true},
		{name: "trims and normalizes", in: " Revoked ", want: ValidationStatusRevoked, ok: true},
		{name: "none is filter only", in: "none", want: ValidationStatusNone, ok: false},
		{name: "unknown value", in: "fake", want: ValidationStatus("fake"), ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseValidationStatus(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("ParseValidationStatus(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}
