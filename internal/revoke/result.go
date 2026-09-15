package revoke

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
)

// Revocation reports only confirmed revocation, an indeterminate outcome, or an
// error. An accepted request is not sufficient evidence of completed revocation.
func parseResult(value any) report.Analysis {
	invalid := func(reason string) report.Analysis {
		return report.Analysis{Status: report.ValidationStatusError, StatusReason: reason}
	}
	result, ok := value.(map[string]any)
	if !ok {
		return invalid(fmt.Sprintf("revocation expression must return an object, got %T", value))
	}
	for key := range result {
		if key != "result" && key != "reason" && key != "metadata" {
			return invalid(fmt.Sprintf("unknown revocation result field %q", key))
		}
	}
	status, ok := result["result"].(string)
	if !ok {
		return invalid("revocation result must be a string")
	}
	outcome := report.Analysis{Status: report.ValidationStatus(strings.ToLower(status))}
	switch outcome.Status {
	case report.ValidationStatusRevoked, report.ValidationStatusUnknown, report.ValidationStatusError:
	default:
		return invalid("revocation result must be one of: revoked, unknown, error")
	}
	if reason, exists := result["reason"]; exists {
		text, ok := reason.(string)
		if !ok {
			return invalid("revocation reason must be a string")
		}
		outcome.StatusReason = text
	}
	if metadata, exists := result["metadata"]; exists && metadata != nil {
		object, ok := metadata.(map[string]any)
		if !ok {
			return invalid("revocation metadata must be an object")
		}
		outcome.StatusMetadata = object
	}
	return outcome
}
