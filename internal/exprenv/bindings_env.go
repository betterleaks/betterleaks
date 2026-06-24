package exprenv

import "strings"

func envNamespace(rt *runtimeBindings) map[string]any {
	return map[string]any{
		"get":          rt.envGet,
		"getOrDefault": rt.envGetOrDefault,
	}
}

// ParseValidationEnvAllowlist converts CLI flag fragments into a set of names.
func ParseValidationEnvAllowlist(parts []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for name := range strings.SplitSeq(part, ",") {
			if n := strings.TrimSpace(name); n != "" {
				out[n] = struct{}{}
			}
		}
	}
	return out
}
