package exprruntime

import "fmt"

// revokeNamespace mirrors validateNamespace, giving `revoke` expressions
// the same "I got a response but don't know how to classify it" escape
// hatch that `validate.unknown` provides.
func revokeNamespace() map[string]any {
	return map[string]any{
		"unknown": unknownRevokeResult,
	}
}

func unknownRevokeResult(resp map[string]any) map[string]any {
	m := map[string]any{"result": "unknown"}
	if status, ok := resp["status"]; ok {
		switch status {
		case int64(429), 429:
			m["reason"] = "rate limited"
		default:
			m["reason"] = fmt.Sprintf("HTTP %v", status)
		}
	}
	return m
}
