package confidence

import (
	"fmt"
	"strings"
)

const Attribute = "confidence"

func Valid(value string) bool {
	return value == "low" || value == "medium" || value == "high"
}

func Parse(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || Valid(value) {
		return value, nil
	}
	return "", fmt.Errorf("invalid confidence %q (expected low, medium, or high)", value)
}

// Meets reports whether a finding confidence meets minimum. Unset or custom
// values are retained for backward compatibility with arbitrary attributes.
func Meets(value, minimum string) bool {
	if minimum == "" || !Valid(value) {
		return true
	}
	return rank(value) >= rank(minimum)
}

func rank(value string) int {
	switch value {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}
