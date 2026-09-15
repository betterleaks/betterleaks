package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/betterleaks/betterleaks/v2/sources"
)

// SchemaVersion identifies the v2 JSON finding and credential report contracts.
const SchemaVersion = 2

const CredentialReportSchemaVersion = SchemaVersion

// CredentialReport is a sanitized direct credential result. Match material and
// source locations are omitted because no source discovery was performed.
type CredentialReport struct {
	SchemaVersion int                            `json:"schema_version"`
	RuleID        string                         `json:"rule_id"`
	Attributes    map[string]string              `json:"attributes,omitempty"`
	Analysis      Analysis                       `json:"analysis,omitzero"`
	ComponentSets []CredentialComponentSetReport `json:"component_sets,omitempty"`
}

// CredentialComponentSetReport describes one resolved credential combination.
type CredentialComponentSetReport struct {
	Components []CredentialComponentReport `json:"components"`
	Analysis   Analysis                    `json:"analysis,omitzero"`
}

// CredentialComponentReport identifies one component and whether the rule
// declares it optional.
type CredentialComponentReport struct {
	RuleID   string   `json:"rule_id"`
	Optional bool     `json:"optional,omitempty"`
	Captures []string `json:"captures,omitempty"`
}

// CredentialRuleList is a versioned list of credential rules and input requirements.
type CredentialRuleList struct {
	SchemaVersion int                     `json:"schema_version"`
	Rules         []CredentialRuleSummary `json:"rules"`
}

// CredentialRuleSummary describes a rule that supports a direct credential command.
type CredentialRuleSummary struct {
	RuleID      string                      `json:"rule_id"`
	Description string                      `json:"description,omitempty"`
	Components  []CredentialComponentReport `json:"components,omitempty"`
	Captures    []string                    `json:"captures,omitempty"`
}

// NewCredentialReport builds a redacted report from a validated or analyzed finding.
func NewCredentialReport(finding Finding, secrets []string) CredentialReport {
	secrets = credentialSecretsForRedaction(secrets)
	result := CredentialReport{
		SchemaVersion: CredentialReportSchemaVersion,
		RuleID:        sanitizeCredentialString(finding.RuleID, secrets),
		Attributes:    sanitizeCredentialAttributes(finding.Attributes, secrets),
		Analysis:      SanitizeAnalysis(finding.Analysis, secrets),
	}
	for _, set := range finding.ComponentSets {
		setResult := CredentialComponentSetReport{
			Analysis: SanitizeAnalysis(set.Analysis, secrets),
		}
		for _, component := range set.Components {
			setResult.Components = append(setResult.Components, CredentialComponentReport{
				RuleID:   sanitizeCredentialString(component.RuleID, secrets),
				Optional: component.Optional,
			})
		}
		sort.Slice(setResult.Components, func(i, j int) bool {
			return setResult.Components[i].RuleID < setResult.Components[j].RuleID
		})
		result.ComponentSets = append(result.ComponentSets, setResult)
	}
	return result
}

func sanitizeCredentialAttributes(attributes map[string]string, secrets []string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		if key == sources.AttrFSFirstFragment || key == sources.AttrPath {
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

// HTTP diagnostics may contain encoded credential values in URLs and bodies.
// Expand only for debug output; normal report metadata retains its usual rules.
func credentialDebugSecretsForRedaction(secrets []string) []string {
	variants := make([]string, 0, len(secrets)*9)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		encoded, _ := json.Marshal(secret)
		jsonValue := string(encoded[1 : len(encoded)-1])
		jsonUnescapedHTML := strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&").Replace(jsonValue)
		variants = append(variants, secret, jsonValue, jsonUnescapedHTML,
			url.QueryEscape(secret), url.PathEscape(secret),
			base64.StdEncoding.EncodeToString([]byte(secret)),
			base64.RawStdEncoding.EncodeToString([]byte(secret)),
			base64.URLEncoding.EncodeToString([]byte(secret)),
			base64.RawURLEncoding.EncodeToString([]byte(secret)))
	}
	return credentialSecretsForRedaction(variants)
}

// CredentialReportFormat identifies a supported direct credential report format.
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
		return "", fmt.Errorf("credential output format must be pretty or jsonl, got %q", format)
	}
	return CredentialReportFormat(format), nil
}

// CredentialReporter renders direct credential results and rule lists.
type CredentialReporter struct {
	Format  CredentialReportFormat
	NoColor bool
	Simple  bool
}

// Write renders a direct credential result.
func (r CredentialReporter) Write(w io.Writer, result CredentialReport) error {
	switch r.Format {
	case CredentialReportFormatPretty:
		if r.Simple {
			return writeCredentialStatus(w, result.Analysis.Status, r.NoColor)
		}
		return writeCredentialText(w, result, r.NoColor)
	case CredentialReportFormatJSONL:
		return writeCredentialJSONL(w, result)
	default:
		return fmt.Errorf("unsupported credential output format %q", r.Format)
	}
}

// WriteRuleList renders the rules that support a direct credential command.
func (r CredentialReporter) WriteRuleList(w io.Writer, result CredentialRuleList) error {
	switch r.Format {
	case CredentialReportFormatPretty:
		return writeCredentialRuleListText(w, result)
	case CredentialReportFormatJSONL:
		return writeCredentialJSONL(w, result)
	default:
		return fmt.Errorf("unsupported credential output format %q", r.Format)
	}
}

func writeCredentialJSONL(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func writeCredentialText(w io.Writer, result CredentialReport, noColor bool) error {
	if _, err := fmt.Fprintf(w, "\n┌─%s──○\n│\n", result.RuleID); err != nil {
		return err
	}
	if err := writeCredentialAnalysis(w, result.Analysis, noColor); err != nil {
		return err
	}

	if len(result.ComponentSets) > 0 {
		if _, err := fmt.Fprintln(w, "│\n│ components:"); err != nil {
			return err
		}
		for _, set := range result.ComponentSets {
			icon := formatCredentialStatusIcon(set.Analysis.Status, noColor)
			if _, err := fmt.Fprintf(w, "│   %s  %s\n", icon, formatCredentialComponents(set.Components)); err != nil {
				return err
			}
			if set.Analysis.StatusReason != "" {
				if _, err := fmt.Fprintf(w, "│      status reason: %s\n", set.Analysis.StatusReason); err != nil {
					return err
				}
			}
			if set.Analysis.Reason != "" {
				if _, err := fmt.Fprintf(w, "│      reason: %s\n", set.Analysis.Reason); err != nil {
					return err
				}
			}
		}
	}
	_, err := fmt.Fprint(w, "└○\n\n")
	return err
}

func writeCredentialAnalysis(w io.Writer, analysis Analysis, noColor bool) error {
	if !analysis.IsZero() {
		if _, err := fmt.Fprintln(w, "│\n│ analysis:"); err != nil {
			return err
		}
		values := analysisDisplayValues(analysis, noColor)
		keys := make([]string, 0, len(values))
		width := 0
		for key, value := range values {
			if value != "" {
				keys = append(keys, key)
				width = max(width, len(key))
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := writeCredentialDotLeader(w, key, values[key], width); err != nil {
				return err
			}
		}
	}
	return nil
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
	return validationStyle(string(status), noColor).Render(text)
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
	return validationStyle(string(status), noColor).Render(icon)
}

func writeCredentialRuleListText(w io.Writer, result CredentialRuleList) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "RULE ID\tCOMPONENTS\tCAPTURES"); err != nil {
		return err
	}
	for _, rule := range result.Rules {
		captures := append([]string(nil), rule.Captures...)
		for _, component := range rule.Components {
			for _, name := range component.Captures {
				captures = append(captures, component.RuleID+":"+name)
			}
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", rule.RuleID, formatCredentialComponents(rule.Components), strings.Join(captures, ", ")); err != nil {
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

func formatMetadataValue(value any) string {
	switch values := value.(type) {
	case []string:
		return "[" + strings.Join(values, ", ") + "]"
	case []any:
		items := make([]string, len(values))
		allStrings := true
		for i, value := range values {
			text, ok := value.(string)
			if !ok {
				allStrings = false
				break
			}
			items[i] = text
		}
		if allStrings {
			return "[" + strings.Join(items, ", ") + "]"
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(encoded)
}
