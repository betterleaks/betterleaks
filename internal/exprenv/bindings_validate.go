package exprenv

import "fmt"

func validateNamespace() map[string]any {
	return map[string]any{
		"unknown": unknownResult,
	}
}

func unknownResult(resp map[string]any) map[string]any {
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
