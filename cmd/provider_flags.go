package cmd

import (
	"fmt"
	"strings"
)

var providerFlagAliases = map[string]string{
	"validation-workers":      "provider-workers",
	"validation-debug":        "provider-debug",
	"validation-timeout":      "provider-timeout",
	"validation-max-requests": "provider-max-requests",
	"validation-rps":          "provider-rps",
	"validation-rps-rule":     "provider-rps-rule",
	"validation-env-vars":     "provider-env-vars",
}

var providerFlagNames = map[string]struct{}{
	"provider-workers":      {},
	"provider-debug":        {},
	"provider-timeout":      {},
	"provider-max-requests": {},
	"provider-rps":          {},
	"provider-rps-rule":     {},
	"provider-env-vars":     {},
}

// normalizeProviderFlagAliases keeps the v1 validation-* request controls
// working without advertising them in help. Mixing old and new spellings is
// rejected because last-flag-wins behavior is too easy to misread in CI.
func normalizeProviderFlagAliases(args []string) ([]string, error) {
	normalized := append([]string(nil), args...)
	type spelling struct{ old, current bool }
	seen := make(map[string]spelling, len(providerFlagAliases))

	for i, argument := range normalized {
		if argument == "--" {
			break
		}
		if !strings.HasPrefix(argument, "--") {
			continue
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, value, hasValue := strings.Cut(nameValue, "=")

		if current, ok := providerFlagAliases[name]; ok {
			state := seen[current]
			state.old = true
			seen[current] = state
			if hasValue {
				normalized[i] = "--" + current + "=" + value
			} else {
				normalized[i] = "--" + current
			}
			continue
		}
		if _, ok := providerFlagNames[name]; ok {
			state := seen[name]
			state.current = true
			seen[name] = state
		}
	}

	for old, current := range providerFlagAliases {
		state := seen[current]
		if state.old && state.current {
			return nil, fmt.Errorf("--%s cannot be combined with its deprecated alias --%s", current, old)
		}
	}
	return normalized, nil
}
