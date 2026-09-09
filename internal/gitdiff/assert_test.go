package gitdiff

import (
	"errors"
	"strings"
	"testing"
)

func assertError(t *testing.T, expected interface{}, actual error, action string) {
	if actual == nil {
		t.Fatalf("expected error %s, but got nil", action)
	}

	switch exp := expected.(type) {
	case bool:
		if !exp {
			t.Fatalf("unexpected error %s: %v", action, actual)
		}
	case string:
		if !strings.Contains(actual.Error(), exp) {
			t.Fatalf("incorrect error %s: %q does not contain %q", action, actual.Error(), exp)
		}
	case error:
		if !errors.Is(actual, exp) {
			t.Fatalf("incorrect error %s: expected %T (%v), actual: %T (%v)", action, exp, exp, actual, actual)
		}
	default:
		t.Fatalf("unsupported expected error type: %T", exp)
	}
}
