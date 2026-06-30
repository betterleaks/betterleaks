package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/internal/validate"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(newValidateCmd())
}

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "validate --rule-id <rule-id> [secret]",
		Short:        "validate a secret with a rule validation expression",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         runValidate,
	}
	cmd.Flags().String("rule-id", "", "rule id whose validation expression should validate the secret")
	cmd.Flags().Bool("secret-stdin", false, "read the primary secret from stdin")
	cmd.Flags().StringArray("component", nil, "required component as rule-id=secret (repeatable)")
	cmd.Flags().StringArray("capture", nil, "validation capture as name=value (repeatable)")
	cmd.Flags().StringArray("set-attr", nil, "set finding/source attribute key=value (repeatable)")
	cmd.Flags().String("format", "text", "output format: text or json")
	return cmd
}

type validateResult struct {
	RuleID       string                `json:"rule_id"`
	Status       string                `json:"status"`
	Reason       string                `json:"reason,omitempty"`
	Metadata     map[string]any        `json:"metadata,omitempty"`
	RequiredSets []validateRequiredSet `json:"required_sets,omitempty"`
}

type validateRequiredSet struct {
	Status     string   `json:"status,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Components []string `json:"components,omitempty"`
}

func runValidate(cmd *cobra.Command, args []string) error {
	ruleID, _ := cmd.Flags().GetString("rule-id")
	if ruleID == "" {
		return errors.New("--rule-id is required")
	}

	secret, err := readValidateSecret(cmd, args)
	if err != nil {
		return err
	}

	resolved, err := resolveConfig(cmd, nil)
	if err != nil {
		return err
	}
	rule, ok := resolved.cfg.Rules[ruleID]
	if !ok {
		return fmt.Errorf("rule %q not found in config", ruleID)
	}
	if strings.TrimSpace(rule.ValidateExpr) == "" {
		return fmt.Errorf("rule %q does not define validation", ruleID)
	}

	rt, err := resolved.cfg.CompileValidation()
	if err != nil {
		return err
	}
	if rt == nil {
		return fmt.Errorf("rule %q does not define validation", ruleID)
	}
	configureValidateRuntime(cmd, rt)

	prg, err := rt.CompileValidation(rule.ValidateExpr)
	if err != nil {
		return fmt.Errorf("compiling rule %s validation: %w", ruleID, err)
	}

	finding, err := buildValidateFinding(cmd, rule, secret)
	if err != nil {
		return err
	}

	var got report.Finding
	emitted := false
	pool := validate.NewPool(1, rt)
	pool.Debug = getBoolFlagDefault(cmd, "validation-debug", false)
	pool.Emit = func(f report.Finding) {
		got = f
		emitted = true
	}
	if err := pool.SubmitContext(cmd.Context(), finding, prg); err != nil {
		pool.Close()
		return err
	}
	pool.Close()
	if !emitted {
		return errors.New("validation did not produce a result")
	}

	result := newValidateResult(got)
	switch format, _ := cmd.Flags().GetString("format"); format {
	case "text":
		return writeValidateText(cmd.OutOrStdout(), result, getBoolFlagDefault(cmd, "no-color", false))
	case "json":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	default:
		return fmt.Errorf("unsupported --format %q", format)
	}
}

func readValidateSecret(cmd *cobra.Command, args []string) (string, error) {
	fromStdin, _ := cmd.Flags().GetBool("secret-stdin")
	if fromStdin && len(args) > 0 {
		return "", errors.New("provide the secret either as an argument or with --secret-stdin, not both")
	}
	if !fromStdin && len(args) == 0 {
		return "", errors.New("secret argument is required unless --secret-stdin is set")
	}
	if !fromStdin {
		return args[0], nil
	}
	data, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return "", fmt.Errorf("reading secret from stdin: %w", err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func configureValidateRuntime(cmd *cobra.Command, rt *exprruntime.Runtime) {
	rt.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(getStringSliceFlagDefault(cmd, "validation-env-vars", nil))
	timeout := getDurationFlagDefault(cmd, "validation-timeout", 10*time.Second)
	if timeout > 0 {
		rt.SetHTTPClient(&http.Client{Timeout: timeout})
	}
}

func buildValidateFinding(cmd *cobra.Command, rule configpkg.Rule, secret string) (report.Finding, error) {
	captures, err := parseSetAttrValues(getStringArrayFlagDefault(cmd, "capture", nil))
	if err != nil {
		return report.Finding{}, fmt.Errorf("invalid --capture value: %w", err)
	}
	attrs, err := parseSetAttrValues(getStringArrayFlagDefault(cmd, "set-attr", nil))
	if err != nil {
		return report.Finding{}, fmt.Errorf("invalid --set-attr value: %w", err)
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	if _, ok := attrs[sources.AttrPath]; !ok {
		attrs[sources.AttrPath] = "betterleaks://validate"
	}

	components, supplied, err := parseValidateComponents(getStringArrayFlagDefault(cmd, "component", nil), captures)
	if err != nil {
		return report.Finding{}, err
	}
	if err := validateRequiredComponents(rule, supplied); err != nil {
		return report.Finding{}, err
	}

	finding := report.Finding{
		RuleID:          rule.RuleID,
		Description:     rule.Description,
		Match:           secret,
		Secret:          secret,
		Line:            secret,
		CaptureGroups:   captures,
		Attributes:      attrs,
		RuleSpecificity: rule.Specificity,
	}
	if len(components) > 0 {
		finding.RequiredSets = []report.RequiredSet{{Components: components}}
	}
	finding.SyncDeprecatedSourceFields()
	finding.SetFingerprint()
	return finding, nil
}

func parseValidateComponents(values []string, captures map[string]string) ([]*report.RequiredFinding, map[string]struct{}, error) {
	components := make([]*report.RequiredFinding, 0, len(values))
	supplied := make(map[string]struct{}, len(values))
	for _, value := range values {
		ruleID, secret, ok := strings.Cut(value, "=")
		if !ok {
			return nil, nil, fmt.Errorf("%q must be in rule-id=secret form", value)
		}
		if ruleID == "" {
			return nil, nil, fmt.Errorf("%q has an empty rule id", value)
		}
		if _, exists := supplied[ruleID]; exists {
			return nil, nil, fmt.Errorf("component %q supplied more than once", ruleID)
		}
		supplied[ruleID] = struct{}{}
		componentCaptures := componentCaptureGroups(ruleID, captures)
		components = append(components, &report.RequiredFinding{
			RuleID:        ruleID,
			Secret:        secret,
			Match:         secret,
			Line:          secret,
			CaptureGroups: componentCaptures,
		})
	}
	return components, supplied, nil
}

func componentCaptureGroups(ruleID string, captures map[string]string) map[string]string {
	prefix := ruleID + ":"
	out := map[string]string{}
	for name, value := range captures {
		if captureName, ok := strings.CutPrefix(name, prefix); ok && captureName != "" {
			out[captureName] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateRequiredComponents(rule configpkg.Rule, supplied map[string]struct{}) error {
	if len(rule.RequiredRules) == 0 {
		return nil
	}
	required := make(map[string]struct{}, len(rule.RequiredRules))
	for _, req := range rule.RequiredRules {
		required[req.RuleID] = struct{}{}
	}

	var missing []string
	for id := range required {
		if _, ok := supplied[id]; !ok {
			missing = append(missing, id)
		}
	}
	var extra []string
	for id := range supplied {
		if _, ok := required[id]; !ok {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		return fmt.Errorf("missing required component(s): %s", strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		return fmt.Errorf("component(s) not required by rule %q: %s", rule.RuleID, strings.Join(extra, ", "))
	}
	return nil
}

func newValidateResult(f report.Finding) validateResult {
	result := validateResult{
		RuleID:   f.RuleID,
		Status:   string(f.ValidationStatus),
		Reason:   f.ValidationReason,
		Metadata: f.ValidationMeta,
	}
	if len(f.RequiredSets) > 0 {
		result.RequiredSets = make([]validateRequiredSet, 0, len(f.RequiredSets))
		for _, set := range f.RequiredSets {
			rs := validateRequiredSet{
				Status: string(set.ValidationStatus),
				Reason: set.ValidationReason,
			}
			for _, component := range set.Components {
				rs.Components = append(rs.Components, component.RuleID)
			}
			sort.Strings(rs.Components)
			result.RequiredSets = append(result.RequiredSets, rs)
		}
	}
	return result
}

func writeValidateText(w io.Writer, result validateResult, noColor bool) error {
	status := report.ValidationStyle(result.Status, noColor).Render(result.Status)
	if _, err := fmt.Fprintf(w, "rule: %s\nstatus: %s\n", result.RuleID, status); err != nil {
		return err
	}
	if result.Reason != "" {
		if _, err := fmt.Fprintf(w, "reason: %s\n", result.Reason); err != nil {
			return err
		}
	}
	if len(result.Metadata) > 0 {
		if _, err := fmt.Fprintln(w, "metadata:"); err != nil {
			return err
		}
		keys := make([]string, 0, len(result.Metadata))
		for key := range result.Metadata {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, err := fmt.Fprintf(w, "  %s: %v\n", key, result.Metadata[key]); err != nil {
				return err
			}
		}
	}
	if len(result.RequiredSets) > 0 {
		if _, err := fmt.Fprintln(w, "required_sets:"); err != nil {
			return err
		}
		for _, set := range result.RequiredSets {
			if _, err := fmt.Fprintf(w, "  - status: %s\n", set.Status); err != nil {
				return err
			}
			if set.Reason != "" {
				if _, err := fmt.Fprintf(w, "    reason: %s\n", set.Reason); err != nil {
					return err
				}
			}
			if len(set.Components) > 0 {
				if _, err := fmt.Fprintf(w, "    components: %s\n", strings.Join(set.Components, ", ")); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func getStringArrayFlagDefault(cmd *cobra.Command, name string, def []string) []string {
	if values, err := cmd.Flags().GetStringArray(name); err == nil {
		return values
	}
	return def
}

func getStringSliceFlagDefault(cmd *cobra.Command, name string, def []string) []string {
	if values, err := cmd.Flags().GetStringSlice(name); err == nil {
		return values
	}
	return def
}

func getBoolFlagDefault(cmd *cobra.Command, name string, def bool) bool {
	if value, err := cmd.Flags().GetBool(name); err == nil {
		return value
	}
	return def
}

func getDurationFlagDefault(cmd *cobra.Command, name string, def time.Duration) time.Duration {
	if value, err := cmd.Flags().GetDuration(name); err == nil {
		return value
	}
	return def
}
