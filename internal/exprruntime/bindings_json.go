package exprruntime

import (
	"encoding/json"
	"fmt"
)

func jsonNamespace() map[string]any {
	return map[string]any{
		"string": jsonString,
	}
}

func jsonString(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("json.string: %w", err)
	}
	return string(b), nil
}
