package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
)

const credentialReportSchemaVersion = 1

// credentialReport keeps validation in its own namespace. Credential access
// analysis can be added later as an "analysis" sibling without changing the
// validation result contract.
type credentialReport struct {
	SchemaVersion int                        `json:"schema_version"`
	RuleID        string                     `json:"rule_id"`
	Validation    credentialValidationReport `json:"validation"`
}

type credentialValidationReport struct {
	Status       report.ValidationStatus       `json:"status"`
	Reason       string                        `json:"reason,omitempty"`
	Metadata     map[string]any                `json:"metadata,omitempty"`
	RequiredSets []credentialRequiredSetReport `json:"required_sets,omitempty"`
}

type credentialRequiredSetReport struct {
	Status     report.ValidationStatus `json:"status,omitempty"`
	Reason     string                  `json:"reason,omitempty"`
	Components []string                `json:"components"`
}

type credentialRuleList struct {
	SchemaVersion int                     `json:"schema_version"`
	Rules         []credentialRuleSummary `json:"rules"`
}

type credentialRuleSummary struct {
	RuleID             string   `json:"rule_id"`
	Description        string   `json:"description,omitempty"`
	RequiredComponents []string `json:"required_components,omitempty"`
}

func newCredentialReport(finding report.Finding, secrets []string, includeEmpty bool) credentialReport {
	secrets = credentialSecretsForRedaction(secrets)
	metadata := sanitizeCredentialMetadata(finding.ValidationMeta, secrets, includeEmpty)
	result := credentialReport{
		SchemaVersion: credentialReportSchemaVersion,
		RuleID:        finding.RuleID,
		Validation: credentialValidationReport{
			Status:   finding.ValidationStatus,
			Reason:   sanitizeCredentialString(finding.ValidationReason, secrets),
			Metadata: metadata,
		},
	}
	for _, set := range finding.RequiredSets {
		setResult := credentialRequiredSetReport{
			Status: set.ValidationStatus,
			Reason: sanitizeCredentialString(set.ValidationReason, secrets),
		}
		for _, component := range set.Components {
			setResult.Components = append(setResult.Components, component.RuleID)
		}
		sort.Strings(setResult.Components)
		result.Validation.RequiredSets = append(result.Validation.RequiredSets, setResult)
	}
	return result
}

func newCredentialRuleList(cfg *configpkg.Config) credentialRuleList {
	result := credentialRuleList{SchemaVersion: credentialReportSchemaVersion}
	seen := make(map[string]struct{}, len(cfg.Rules))
	for _, id := range sortedRuleIDs(cfg) {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		rule := cfg.Rules[id]
		if strings.TrimSpace(rule.ValidateExpr) == "" {
			continue
		}
		summary := credentialRuleSummary{
			RuleID:      rule.RuleID,
			Description: rule.Description,
		}
		for _, required := range rule.RequiredRules {
			summary.RequiredComponents = append(summary.RequiredComponents, required.RuleID)
		}
		sort.Strings(summary.RequiredComponents)
		result.Rules = append(result.Rules, summary)
	}
	return result
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

func writeCredentialReport(cmd *cobra.Command, result credentialReport) error {
	noColor, err := cmd.Flags().GetBool("no-color")
	if err != nil {
		return err
	}
	simple, err := cmd.Flags().GetBool("simple")
	if err != nil {
		return err
	}
	path, err := cmd.Flags().GetString("report-path")
	if err != nil {
		return err
	}
	if path != "" && path != report.StdoutReportPath {
		noColor = true
	}
	writeText := func(w io.Writer) error {
		if simple {
			return writeCredentialStatus(w, result.Validation.Status, noColor)
		}
		return writeCredentialText(w, result, noColor)
	}
	return writeCredentialOutput(
		cmd,
		writeText,
		result,
	)
}

func writeCredentialRuleList(cmd *cobra.Command, result credentialRuleList) error {
	return writeCredentialOutput(
		cmd,
		func(w io.Writer) error { return writeCredentialRuleListText(w, result) },
		result,
	)
}

func writeCredentialOutput(cmd *cobra.Command, writeText func(io.Writer) error, jsonValue any) (returnErr error) {
	format, err := credentialReportFormat(cmd)
	if err != nil {
		return err
	}
	path, err := cmd.Flags().GetString("report-path")
	if err != nil {
		return err
	}

	var writer io.Writer = cmd.OutOrStdout()
	if path != "" && path != report.StdoutReportPath {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("opening validation report %q: %w", path, err)
		}
		writer = file
		defer func() {
			if err := file.Close(); returnErr == nil && err != nil {
				returnErr = fmt.Errorf("closing validation report %q: %w", path, err)
			}
		}()
	}

	switch format {
	case "text":
		return writeText(writer)
	case "json":
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		return encoder.Encode(jsonValue)
	default:
		return fmt.Errorf("unsupported validation report format %q", format)
	}
}

func credentialReportFormat(cmd *cobra.Command) (string, error) {
	templatePath, err := cmd.Flags().GetString("report-template")
	if err != nil {
		return "", err
	}
	if templatePath != "" {
		return "", errors.New("--report-template is not supported by validate; use --report-format text or json")
	}

	format, err := cmd.Flags().GetString("report-format")
	if err != nil {
		return "", err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		path, err := cmd.Flags().GetString("report-path")
		if err != nil {
			return "", err
		}
		if strings.EqualFold(filepath.Ext(path), ".json") {
			return "json", nil
		}
		return "text", nil
	}
	if format != "text" && format != "json" {
		return "", fmt.Errorf("--report-format must be text or json for validate, got %q", format)
	}
	return format, nil
}

func writeCredentialText(w io.Writer, result credentialReport, noColor bool) error {
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

	if len(result.Validation.RequiredSets) > 0 {
		if _, err := fmt.Fprintln(w, "│\n│ components:"); err != nil {
			return err
		}
		for _, set := range result.Validation.RequiredSets {
			icon := formatCredentialStatusIcon(set.Status, noColor)
			if _, err := fmt.Fprintf(w, "│   %s  %s\n", icon, strings.Join(set.Components, ", ")); err != nil {
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

func writeCredentialStatus(w io.Writer, status report.ValidationStatus, noColor bool) error {
	_, err := fmt.Fprintln(w, formatCredentialStatus(status, noColor))
	return err
}

func writeCredentialDotLeader(w io.Writer, key, value string, maxKey int) error {
	dots := strings.Repeat(".", maxKey+6-len(key))
	_, err := fmt.Fprintf(w, "│   %s %s %s\n", key, dots, value)
	return err
}

func formatCredentialStatus(status report.ValidationStatus, noColor bool) string {
	text := strings.ToUpper(string(status))
	return report.ValidationStyle(string(status), noColor).Render(text)
}

func formatCredentialStatusIcon(status report.ValidationStatus, noColor bool) string {
	var icon string
	switch status {
	case report.ValidationStatusValid:
		icon = "✓"
	case report.ValidationStatusInvalid, report.ValidationStatusError:
		icon = "✗"
	case report.ValidationStatusRevoked:
		icon = "!"
	case report.ValidationStatusNeedsValidation, report.ValidationStatusUnknown:
		icon = "?"
	default:
		icon = "-"
	}
	return report.ValidationStyle(string(status), noColor).Render(icon)
}

func writeCredentialRuleListText(w io.Writer, result credentialRuleList) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "RULE ID\tREQUIRED COMPONENTS"); err != nil {
		return err
	}
	for _, rule := range result.Rules {
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", rule.RuleID, strings.Join(rule.RequiredComponents, ", ")); err != nil {
			return err
		}
	}
	return tw.Flush()
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
