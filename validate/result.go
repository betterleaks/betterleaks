package validate

import (
	"fmt"
	"reflect"

	"github.com/betterleaks/betterleaks/report"
	"github.com/google/cel-go/common/types/ref"
)

var mapAnyType = reflect.TypeFor[map[string]any]()

// Result holds the outcome of a CEL validation evaluation.
type Result struct {
	Status   report.ValidationStatus // "valid", "invalid", "revoked", "unknown", "error"
	Reason   string                  // human-readable explanation
	Metadata map[string]any          // extra fields from the CEL result map
}

// ParseResult interprets the CEL output value into a Result.
func ParseResult(val ref.Val) *Result {
	switch v := val.Value().(type) {
	case map[string]any:
		return parseResultMap(v)

	default:
		nativeVal, err := val.ConvertToNative(mapAnyType)
		if err == nil {
			if m, ok := nativeVal.(map[string]any); ok {
				return parseResultMap(m)
			}
		}
		return &Result{
			Status:   report.ValidationStatusError,
			Reason:   fmt.Sprintf("expression returned unexpected type: %T", val.Value()),
			Metadata: map[string]any{},
		}
	}
}

// statusPriority defines precedence for status rollup.
// Higher value = higher priority. "valid" wins over everything; "" loses to everything.
var statusPriority = map[report.ValidationStatus]int{
	"":                             0,
	report.ValidationStatusError:   1,
	report.ValidationStatusInvalid: 2,
	report.ValidationStatusUnknown: 3,
	report.ValidationStatusRevoked: 4,
	report.ValidationStatusValid:   5,
}

// BetterStatus returns whichever of a or b has higher priority.
// Priority order: valid > revoked > unknown > invalid > error > "".
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

// parseResultMap interprets a map result from a CEL expression.
//
// The expected form is {"result": "<status>", ...} where <status> is one of
// the report.ValidationStatus constants.
func parseResultMap(m map[string]any) *Result {
	result := &Result{
		Status:   report.ValidationStatusUnknown,
		Metadata: make(map[string]any),
	}

	// Primary: explicit "result" key with a string status.
	if v, ok := m["result"]; ok {
		if s, ok := v.(string); ok {
			status, ok := report.ParseValidationStatus(s)
			if ok {
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
