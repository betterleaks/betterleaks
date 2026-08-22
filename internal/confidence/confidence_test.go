package confidence

import "testing"

func TestMeets(t *testing.T) {
	for _, tc := range []struct {
		value, minimum string
		want           bool
	}{
		{"low", "medium", false},
		{"medium", "medium", true},
		{"high", "medium", true},
		{"", "high", true},
		{"custom", "high", true},
	} {
		if got := Meets(tc.value, tc.minimum); got != tc.want {
			t.Fatalf("Meets(%q, %q) = %v, want %v", tc.value, tc.minimum, got, tc.want)
		}
	}

	if got, err := Parse(" HIGH "); err != nil || got != "high" {
		t.Fatalf("Parse(HIGH) = %q, %v", got, err)
	}
	if _, err := Parse("certain"); err == nil {
		t.Fatal("Parse(certain) succeeded")
	}
}
