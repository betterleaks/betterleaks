package validate

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/report"
)

// validStatuses is the set of recognised validation statuses.
var validStatuses = map[report.ValidationStatus]bool{
	report.ValidationStatusValid:           true,
	report.ValidationStatusNeedsValidation: true,
	report.ValidationStatusInvalid:         true,
	report.ValidationStatusRevoked:         true,
	report.ValidationStatusUnknown:         true,
	report.ValidationStatusError:           true,
}

// Result holds the outcome of a validation expression evaluation.
type Result struct {
	Status   report.ValidationStatus // valid, invalid, revoked, unknown, error
	Reason   string                  // human-readable explanation
	Metadata map[string]any          // extra fields from the validation result map
}

// ParseResult interprets the expression output value into a Result.
func ParseResult(val any) *Result {
	switch v := val.(type) {
	case map[string]any:
		return parseResultMap(v)
	case map[any]any:
		m := make(map[string]any, len(v))
		for k, value := range v {
			if s, ok := k.(string); ok {
				m[s] = value
			}
		}
		return parseResultMap(m)
	default:
		return &Result{
			Status:   report.ValidationStatusError,
			Reason:   fmt.Sprintf("expression returned unexpected type: %T", val),
			Metadata: map[string]any{},
		}
	}
}

// statusPriority defines precedence for status rollup.
// Higher value = higher priority. "valid" wins over everything; "" loses to everything.
var statusPriority = map[report.ValidationStatus]int{
	report.ValidationStatusNone:            0,
	report.ValidationStatusError:           1,
	report.ValidationStatusInvalid:         2,
	report.ValidationStatusUnknown:         3,
	report.ValidationStatusRevoked:         4,
	report.ValidationStatusNeedsValidation: 5,
	report.ValidationStatusValid:           6,
}

// BetterStatus returns whichever of a or b has higher priority.
// Priority order: valid > needs_validation > revoked > unknown > invalid > error > "".
// This is used for rolling up per-component validation results into an
// overall finding-level status for composite rules.
func BetterStatus(a, b report.ValidationStatus) report.ValidationStatus {
	if statusPriority[b] > statusPriority[a] {
		return b
	}
	return a
}

// reservedKeys are map keys consumed by parseResultMap and excluded from metadata.
var reservedKeys = map[string]bool{
	"result": true, "reason": true,
}

// parseResultMap interprets a map result from a validation expression.
//
// The expected form is {"result": "<status>", ...} where <status> is one of
// the validStatuses.
func parseResultMap(m map[string]any) *Result {
	result := &Result{
		Status:   report.ValidationStatusUnknown,
		Metadata: make(map[string]any),
	}

	// Primary: explicit "result" key with a string status.
	if v, ok := m["result"]; ok {
		if s, ok := v.(string); ok {
			status := report.ValidationStatus(strings.ToLower(s))
			if validStatuses[status] {
				result.Status = status
			}
		}
	}

	// Extract reason.
	if r, ok := m["reason"]; ok {
		if s, ok := r.(string); ok {
			result.Reason = s
		}
	}

	// Everything else is metadata.
	for k, v := range m {
		if !reservedKeys[k] {
			result.Metadata[k] = v
		}
	}

	return result
}
