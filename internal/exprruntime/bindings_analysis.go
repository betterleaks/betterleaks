package exprruntime

import (
	"fmt"
)

// The result parser remains the authority for the public capability schema.
// Keeping this small ordered vocabulary here avoids coupling the Expr runtime
// to the report package, which is higher in the dependency graph.
var analysisCapabilityOrder = [...]string{
	"read",
	"write",
	"read_secrets",
	"create_credentials",
	"manage_users",
	"admin",
}

func analysisNamespace() map[string]any {
	return map[string]any{
		"capabilities": analysisCapabilities,
	}
}

// analysisCapabilities turns capability predicates into the positive-only
// list accepted by the analysis result contract.
func analysisCapabilities(value any) ([]string, error) {
	conditions, ok := analysisConditionMap(value)
	if !ok {
		return nil, fmt.Errorf("analysis.capabilities: expected an object, got %T", value)
	}

	for capability, enabled := range conditions {
		if !knownAnalysisCapability(capability) {
			return nil, fmt.Errorf("analysis.capabilities: unknown capability %q", capability)
		}
		if _, ok := enabled.(bool); !ok {
			return nil, fmt.Errorf("analysis.capabilities: %q must be a boolean", capability)
		}
	}

	result := make([]string, 0, len(conditions))
	for _, capability := range analysisCapabilityOrder {
		if enabled, _ := conditions[capability].(bool); enabled {
			result = append(result, capability)
		}
	}
	return result, nil
}

func knownAnalysisCapability(name string) bool {
	for _, capability := range analysisCapabilityOrder {
		if capability == name {
			return true
		}
	}
	return false
}

func analysisConditionMap(value any) (map[string]any, bool) {
	switch value := value.(type) {
	case map[string]any:
		return value, true
	case map[string]bool:
		result := make(map[string]any, len(value))
		for key, enabled := range value {
			result[key] = enabled
		}
		return result, true
	case map[any]any:
		result := make(map[string]any, len(value))
		for key, enabled := range value {
			name, ok := key.(string)
			if !ok {
				return nil, false
			}
			result[name] = enabled
		}
		return result, true
	default:
		return nil, false
	}
}
