package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
)

var validCapabilities = map[report.Capability]struct{}{
	report.CapabilityRead:              {},
	report.CapabilityWrite:             {},
	report.CapabilityReadSecrets:       {},
	report.CapabilityCreateCredentials: {},
	report.CapabilityManageUsers:       {},
	report.CapabilityAdmin:             {},
}

// ParseResult validates and normalizes the output of an analysis expression.
// The schema is intentionally closed so provider-specific data cannot leak
// into the stable report contract by accident.
func ParseResult(value any) (report.Analysis, error) {
	result, ok := stringMap(value)
	if !ok {
		return report.Analysis{}, fmt.Errorf("analysis expression returned unexpected type: %T", value)
	}
	if err := rejectUnknownFields(result, "analysis", "reason", "identity", "capabilities", "metadata"); err != nil {
		return report.Analysis{}, err
	}

	analysis := report.Analysis{}
	if rawReason, exists := result["reason"]; exists {
		reason, ok := rawReason.(string)
		if !ok {
			return report.Analysis{}, fmt.Errorf("analysis reason must be a string")
		}
		analysis.Reason = strings.TrimSpace(reason)
	}

	if rawIdentity, exists := result["identity"]; exists && rawIdentity != nil {
		identity, err := parseIdentity(rawIdentity)
		if err != nil {
			return report.Analysis{}, err
		}
		analysis.Identity = identity
	}

	if rawCapabilities, exists := result["capabilities"]; exists && rawCapabilities != nil {
		capabilities, err := parseCapabilities(rawCapabilities)
		if err != nil {
			return report.Analysis{}, err
		}
		analysis.Capabilities = capabilities
	}

	if rawMetadata, exists := result["metadata"]; exists && rawMetadata != nil {
		metadata, ok := stringMap(rawMetadata)
		if !ok {
			return report.Analysis{}, fmt.Errorf("analysis metadata must be an object")
		}
		analysis.Metadata = metadata
	}

	analysis.Severity = report.AnalysisSeverity(analysis.Capabilities)
	return analysis, nil
}

func parseIdentity(value any) (*report.AnalysisIdentity, error) {
	raw, ok := stringMap(value)
	if !ok {
		return nil, fmt.Errorf("analysis identity must be an object")
	}
	if err := rejectUnknownFields(raw, "analysis identity", "id", "username", "name", "email", "account"); err != nil {
		return nil, err
	}

	identity := report.AnalysisIdentity{}
	for _, field := range []struct {
		key         string
		destination *string
	}{
		{key: "id", destination: &identity.ID},
		{key: "username", destination: &identity.Username},
		{key: "name", destination: &identity.Name},
		{key: "email", destination: &identity.Email},
	} {
		key, destination := field.key, field.destination
		if rawValue, exists := raw[key]; exists && rawValue != nil {
			text, ok := rawValue.(string)
			if !ok {
				return nil, fmt.Errorf("analysis identity %s must be a string", key)
			}
			*destination = strings.TrimSpace(text)
		}
	}
	if rawAccount, exists := raw["account"]; exists && rawAccount != nil {
		account, err := parseAccount(rawAccount)
		if err != nil {
			return nil, err
		}
		identity.Account = account
	}
	if identity.ID == "" && identity.Username == "" && identity.Name == "" &&
		identity.Email == "" && identity.Account == nil {
		return nil, nil
	}
	return &identity, nil
}

func parseAccount(value any) (*report.AnalysisAccount, error) {
	raw, ok := stringMap(value)
	if !ok {
		return nil, fmt.Errorf("analysis identity account must be an object")
	}
	if err := rejectUnknownFields(raw, "analysis identity account", "id", "name", "domains"); err != nil {
		return nil, err
	}

	account := report.AnalysisAccount{}
	for _, field := range []struct {
		key         string
		destination *string
	}{
		{key: "id", destination: &account.ID},
		{key: "name", destination: &account.Name},
	} {
		key, destination := field.key, field.destination
		if rawValue, exists := raw[key]; exists && rawValue != nil {
			text, ok := rawValue.(string)
			if !ok {
				return nil, fmt.Errorf("analysis identity account %s must be a string", key)
			}
			*destination = strings.TrimSpace(text)
		}
	}
	if rawDomains, exists := raw["domains"]; exists && rawDomains != nil {
		domains, err := stringSlice(rawDomains, "analysis identity account domains")
		if err != nil {
			return nil, err
		}
		seen := make(map[string]struct{}, len(domains))
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			if _, exists := seen[domain]; exists {
				continue
			}
			seen[domain] = struct{}{}
			account.Domains = append(account.Domains, domain)
		}
		sort.Strings(account.Domains)
	}
	if account.ID == "" && account.Name == "" && len(account.Domains) == 0 {
		return nil, nil
	}
	return &account, nil
}

func parseCapabilities(value any) ([]report.Capability, error) {
	values, err := stringSlice(value, "analysis capabilities")
	if err != nil {
		return nil, err
	}
	seen := make(map[report.Capability]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		capability := report.Capability(value)
		if _, ok := validCapabilities[capability]; !ok {
			return nil, fmt.Errorf("unknown analysis capability %q", value)
		}
		seen[capability] = struct{}{}
	}
	capabilities := make([]report.Capability, 0, len(seen))
	for _, capability := range report.KnownCapabilities() {
		if _, ok := seen[capability]; ok {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities, nil
}

func stringSlice(value any, field string) ([]string, error) {
	switch values := value.(type) {
	case []string:
		return values, nil
	case []any:
		result := make([]string, len(values))
		for i, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%s must contain only strings", field)
			}
			result[i] = text
		}
		return result, nil
	default:
		return nil, fmt.Errorf("%s must be an array", field)
	}
}

func stringMap(value any) (map[string]any, bool) {
	switch value := value.(type) {
	case map[string]any:
		return value, true
	case map[any]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			text, ok := key.(string)
			if !ok {
				return nil, false
			}
			result[text] = item
		}
		return result, true
	default:
		return nil, false
	}
}

func rejectUnknownFields(values map[string]any, object string, allowed ...string) error {
	known := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		known[field] = struct{}{}
	}
	var unknown []string
	for field := range values {
		if _, ok := known[field]; !ok {
			unknown = append(unknown, field)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s contains unknown field %q", object, unknown[0])
}
