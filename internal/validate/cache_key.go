package validate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// CacheKey identifies a validation input. Captures and components occupy
// separate namespaces so identical user-defined keys cannot collide.
func CacheKey(ruleID, secret string, captures map[string]string, components map[string]cacheComponent) string {
	encoded, err := json.Marshal(struct {
		RuleID     string                    `json:"rule_id"`
		Secret     string                    `json:"secret"`
		Captures   map[string]string         `json:"captures,omitempty"`
		Components map[string]cacheComponent `json:"components,omitempty"`
	}{
		RuleID:     ruleID,
		Secret:     secret,
		Captures:   captures,
		Components: components,
	})
	if err != nil {
		panic(fmt.Sprintf("encode validation cache key: %v", err))
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

type cacheComponent struct {
	Secret string `json:"secret"`
	// Captures contains named regex capture groups only.
	Captures map[string]string `json:"captures,omitempty"`
}
