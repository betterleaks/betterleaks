package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/betterleaks/betterleaks/sources"
)

const CredentialReportSchemaVersion = 1

// CredentialReport keeps validation in its own namespace. Credential access
// analysis can be added later as an "analysis" sibling without changing the
// validation result contract.
type CredentialReport struct {
	SchemaVersion int                        `json:"schema_version"`
	RuleID        string                     `json:"rule_id"`
	Attributes    map[string]string          `json:"attributes,omitempty"`
	Validation    CredentialValidationReport `json:"validation"`
}

// CredentialValidationReport is the validation portion of a credential report.
type CredentialValidationReport struct {
	Status        ValidationStatus               `json:"status"`
	Reason        string                         `json:"reason,omitempty"`
	Metadata      map[string]any                 `json:"metadata,omitempty"`
	ComponentSets []CredentialComponentSetReport `json:"component_sets,omitempty"`
}

// CredentialComponentSetReport describes one validated set of companion credentials.
type CredentialComponentSetReport struct {
	Status     ValidationStatus            `json:"status,omitempty"`
	Reason     string                      `json:"reason,omitempty"`
	Components []CredentialComponentReport `json:"components"`
}

// CredentialComponentReport identifies one component and whether the rule
// declares it optional.
type CredentialComponentReport struct {
	RuleID   string `json:"rule_id"`
	Optional bool   `json:"optional,omitempty"`
}

// CredentialRuleList is the versioned output produced by validate --list.
type CredentialRuleList struct {
	SchemaVersion int                     `json:"schema_version"`
	Rules         []CredentialRuleSummary `json:"rules"`
}

// CredentialRuleSummary describes a rule that supports direct validation.
type CredentialRuleSummary struct {
	RuleID      string                      `json:"rule_id"`
	Description string                      `json:"description,omitempty"`
	Components  []CredentialComponentReport `json:"components,omitempty"`
	Captures    []string                    `json:"captures,omitempty"`
}

// NewCredentialReport builds a redacted report from a validated finding.
func NewCredentialReport(finding Finding, secrets []string, includeEmpty bool) CredentialReport {
	secrets = credentialSecretsForRedaction(secrets)
	metadata := sanitizeCredentialMetadata(finding.Validation.Metadata, secrets, includeEmpty)
	result := CredentialReport{
		SchemaVersion: CredentialReportSchemaVersion,
		RuleID:        finding.RuleID,
		Attributes:    sanitizeCredentialAttributes(finding.Attributes, secrets),
		Validation: CredentialValidationReport{
			Status:   finding.Validation.Status,
			Reason:   sanitizeCredentialString(finding.Validation.Reason, secrets),
			Metadata: metadata,
		},
	}
	for _, set := range finding.ComponentSets {
		setResult := CredentialComponentSetReport{
			Status: set.Validation.Status,
			Reason: sanitizeCredentialString(set.Validation.Reason, secrets),
		}
		for _, component := range set.Components {
			setResult.Components = append(setResult.Components, CredentialComponentReport{
				RuleID:   component.RuleID,
				Optional: component.Optional,
			})
		}
		sort.Slice(setResult.Components, func(i, j int) bool {
			return setResult.Components[i].RuleID < setResult.Components[j].RuleID
		})
		result.Validation.ComponentSets = append(result.Validation.ComponentSets, setResult)
	}
	return result
}

func sanitizeCredentialAttributes(attributes map[string]string, secrets []string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		if key == sources.AttrFSFirstFragment {
			continue
		}
		out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialString(value, secrets)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeCredentialMetadata(metadata map[string]any, secrets []string, includeEmpty bool) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if !includeEmpty {
			if value == nil {
				continue
			}
			if text, ok := value.(string); ok && text == "" {
				continue
			}
		}
		out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialValue(value, secrets)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeCredentialValue(value any, secrets []string) any {
	switch typed := value.(type) {
	case string:
		return sanitizeCredentialString(typed, secrets)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialValue(child, secrets)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, child := range typed {
			out[sanitizeCredentialString(key, secrets)] = sanitizeCredentialString(child, secrets)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = sanitizeCredentialValue(child, secrets)
		}
		return out
	case []string:
		out := make([]string, len(typed))
		for i, child := range typed {
			out[i] = sanitizeCredentialString(child, secrets)
		}
		return out
	default:
		return value
	}
}

func sanitizeCredentialString(value string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[redacted]")
		}
	}
	return value
}

func credentialSecretsForRedaction(secrets []string) []string {
	ordered := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if _, ok := seen[secret]; ok {
			continue
		}
		seen[secret] = struct{}{}
		ordered = append(ordered, secret)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return len(ordered[i]) > len(ordered[j])
	})
	return ordered
}

// CredentialReportFormat identifies a supported direct-validation report format.
type CredentialReportFormat string

const (
	CredentialReportFormatPretty CredentialReportFormat = "pretty"
	CredentialReportFormatJSONL  CredentialReportFormat = "jsonl"
)

// ResolveCredentialReportFormat validates an explicit format. Pretty output is
// the default; JSONL emits one compact credential record per line.
func ResolveCredentialReportFormat(format string) (CredentialReportFormat, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return CredentialReportFormatPretty, nil
	}
	if format != "pretty" && format != "jsonl" {
		return "", fmt.Errorf("validate output format must be pretty or jsonl, got %q", format)
	}
	return CredentialReportFormat(format), nil
}

// CredentialReporter renders direct-validation results and rule lists.
type CredentialReporter struct {
	Format  CredentialReportFormat
	NoColor bool
	Simple  bool
}

// Write renders a direct-validation result.
func (r CredentialReporter) Write(w io.Writer, result CredentialReport) error {
	switch r.Format {
	case CredentialReportFormatPretty:
		if r.Simple {
			return writeCredentialStatus(w, result.Validation.Status, r.NoColor)
		}
		return writeCredentialText(w, result, r.NoColor)
	case CredentialReportFormatJSONL:
		return writeCredentialJSONL(w, result)
	default:
		return fmt.Errorf("unsupported validate output format %q", r.Format)
	}
}

// WriteRuleList renders the rules that support direct validation.
func (r CredentialReporter) WriteRuleList(w io.Writer, result CredentialRuleList) error {
	switch r.Format {
	case CredentialReportFormatPretty:
		return writeCredentialRuleListText(w, result)
	case CredentialReportFormatJSONL:
		return writeCredentialJSONL(w, result)
	default:
		return fmt.Errorf("unsupported validate output format %q", r.Format)
	}
}

func writeCredentialJSONL(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func writeCredentialText(w io.Writer, result CredentialReport, noColor bool) error {
	if _, err := fmt.Fprintf(w, "\n┌─%s──○\n│\n│ validation:\n", result.RuleID); err != nil {
		return err
	}

	maxKey := len("status")
	if result.Validation.Reason != "" {
		maxKey = max(maxKey, len("reason"))
	}
	for key := range result.Validation.Metadata {
		maxKey = max(maxKey, len(key))
	}

	status := formatCredentialStatus(result.Validation.Status, noColor)
	if err := writeCredentialDotLeader(w, "status", status, maxKey); err != nil {
		return err
	}
	if result.Validation.Reason != "" {
		if err := writeCredentialDotLeader(w, "reason", result.Validation.Reason, maxKey); err != nil {
			return err
		}
	}
	for _, key := range sortedAnyMapKeys(result.Validation.Metadata) {
		if err := writeCredentialDotLeader(w, key, formatCredentialValue(result.Validation.Metadata[key]), maxKey); err != nil {
			return err
		}
	}

	if len(result.Validation.ComponentSets) > 0 {
		if _, err := fmt.Fprintln(w, "│\n│ components:"); err != nil {
			return err
		}
		for _, set := range result.Validation.ComponentSets {
			icon := formatCredentialStatusIcon(set.Status, noColor)
			if _, err := fmt.Fprintf(w, "│   %s  %s\n", icon, formatCredentialComponents(set.Components)); err != nil {
				return err
			}
			if set.Reason != "" {
				if _, err := fmt.Fprintf(w, "│      reason: %s\n", set.Reason); err != nil {
					return err
				}
			}
		}
	}
	_, err := fmt.Fprint(w, "└○\n\n")
	return err
}

func writeCredentialStatus(w io.Writer, status ValidationStatus, noColor bool) error {
	_, err := fmt.Fprintln(w, formatCredentialStatus(status, noColor))
	return err
}

func writeCredentialDotLeader(w io.Writer, key, value string, maxKey int) error {
	dots := strings.Repeat(".", maxKey+6-len(key))
	_, err := fmt.Fprintf(w, "│   %s %s %s\n", key, dots, value)
	return err
}

func formatCredentialStatus(status ValidationStatus, noColor bool) string {
	text := strings.ToUpper(string(status))
	return ValidationStyle(string(status), noColor).Render(text)
}

func formatCredentialStatusIcon(status ValidationStatus, noColor bool) string {
	var icon string
	switch status {
	case ValidationStatusValid:
		icon = "✓"
	case ValidationStatusInvalid, ValidationStatusError:
		icon = "✗"
	case ValidationStatusRevoked:
		icon = "!"
	case ValidationStatusNeedsValidation, ValidationStatusUnknown:
		icon = "?"
	default:
		icon = "-"
	}
	return ValidationStyle(string(status), noColor).Render(icon)
}

func writeCredentialRuleListText(w io.Writer, result CredentialRuleList) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "RULE ID\tCOMPONENTS\tCAPTURES"); err != nil {
		return err
	}
	for _, rule := range result.Rules {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", rule.RuleID, formatCredentialComponents(rule.Components), strings.Join(rule.Captures, ", ")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func formatCredentialComponents(components []CredentialComponentReport) string {
	formatted := make([]string, 0, len(components))
	for _, component := range components {
		label := component.RuleID
		if component.Optional {
			label += " (optional)"
		}
		formatted = append(formatted, label)
	}
	return strings.Join(formatted, ", ")
}

func sortedAnyMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func formatCredentialValue(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}
