package provider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// CacheKey identifies a credential, not an occurrence. Source provenance and
// context are intentionally excluded so repeated credentials share provider work.
// Captures and components occupy separate namespaces to prevent collisions.
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
