package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	validatepkg "github.com/betterleaks/betterleaks/internal/validate"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

const maxValidateCredentialInputBytes = 1 << 20

func init() {
	rootCmd.AddCommand(newValidateCmd())
}

func newValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "validate --rule-id <rule-id> [secret]",
		Short:        "validate a known secret without running detection",
		Long:         "Validate a known secret without running detection.\n\nWhen [secret] is omitted, input is read from piped or redirected stdin automatically. A JSON object is treated as a multipart credential.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         runValidate,
	}
	cmd.Flags().String("rule-id", "", "rule whose validation expression should validate the secret")
	cmd.Flags().StringArray("component", nil, "required credential component as rule-id=secret (repeatable)")
	cmd.Flags().StringArray("capture", nil, "validation capture as name=value; use rule-id:name=value for a component (repeatable)")
	cmd.Flags().Bool("list", false, "list rules that support direct validation")
	cmd.Flags().Bool("simple", false, "print only the validation status")
	return cmd
}

func runValidate(cmd *cobra.Command, args []string) error {
	format, err := credentialReportFormat(cmd)
	if err != nil {
		return err
	}
	simple, err := cmd.Flags().GetBool("simple")
	if err != nil {
		return err
	}
	if simple && format != "text" {
		return errors.New("--simple only supports text output; remove --report-format or use --report-format text")
	}

	list, err := cmd.Flags().GetBool("list")
	if err != nil {
		return err
	}
	if list {
		if err := validateListMode(cmd, args); err != nil {
			return err
		}
		resolved, err := resolveConfig(cmd, nil)
		if err != nil {
			return err
		}
		return writeCredentialRuleList(cmd, newCredentialRuleList(resolved.cfg))
	}

	ruleID, err := cmd.Flags().GetString("rule-id")
	if err != nil {
		return err
	}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return errors.New("--rule-id is required (use --list to see rules with validation)")
	}

	input, err := readValidateCredentialInput(cmd, args)
	if err != nil {
		return err
	}

	resolved, err := resolveConfig(cmd, nil)
	if err != nil {
		return err
	}
	rule, ok := resolved.cfg.Rules[ruleID]
	if !ok {
		return unknownValidationRuleError(resolved.cfg, ruleID)
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
	if err := configureCredentialRuntime(cmd, rt); err != nil {
		return err
	}

	program, err := rt.CompileValidation(rule.ValidateExpr)
	if err != nil {
		return fmt.Errorf("compiling rule %s validation: %w", ruleID, err)
	}

	finding, suppliedSecrets, err := buildValidateFinding(rule, input)
	if err != nil {
		return err
	}

	debug, err := cmd.Flags().GetBool("validation-debug")
	if err != nil {
		return err
	}
	validated, err := evaluateCredential(cmd.Context(), rt, program, finding, debug)
	if err != nil {
		return err
	}

	includeEmpty, err := cmd.Flags().GetBool("validation-extract-empty")
	if err != nil {
		return err
	}
	result := newCredentialReport(validated, suppliedSecrets, includeEmpty)
	return writeCredentialReport(cmd, result)
}

func validateListMode(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return errors.New("--list does not accept a secret")
	}
	for _, name := range []string{"rule-id", "component", "capture", "simple"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--list cannot be combined with --%s", name)
		}
	}
	return nil
}

type validateCredentialInput struct {
	Secret     string            `json:"secret"`
	Components map[string]string `json:"components,omitempty"`
	Captures   map[string]string `json:"captures,omitempty"`
}

func readValidateCredentialInput(cmd *cobra.Command, args []string) (validateCredentialInput, error) {
	var secret string
	if len(args) == 0 {
		if !validateStdinAvailable(cmd.InOrStdin()) {
			return validateCredentialInput{}, errors.New("secret argument or piped credential is required")
		}
		data, err := readLimitedValidateStdin(cmd)
		if err != nil {
			return validateCredentialInput{}, err
		}
		if validateCredentialInputIsJSON(data) {
			for _, name := range []string{"component", "capture"} {
				if cmd.Flags().Changed(name) {
					return validateCredentialInput{}, fmt.Errorf("piped credential JSON cannot be combined with --%s", name)
				}
			}
			return decodeValidateCredentialInput(data)
		}
		secret, err = validateSecretFromBytes(data)
		if err != nil {
			return validateCredentialInput{}, err
		}
	} else {
		var err error
		secret, err = validateSecretFromBytes([]byte(args[0]))
		if err != nil {
			return validateCredentialInput{}, err
		}
	}
	captureValues, err := cmd.Flags().GetStringArray("capture")
	if err != nil {
		return validateCredentialInput{}, err
	}
	captures, err := parseUniqueAssignments(captureValues)
	if err != nil {
		return validateCredentialInput{}, fmt.Errorf("invalid --capture value: %w", err)
	}
	componentValues, err := cmd.Flags().GetStringArray("component")
	if err != nil {
		return validateCredentialInput{}, err
	}
	components, err := parseValidateComponentAssignments(componentValues)
	if err != nil {
		return validateCredentialInput{}, err
	}

	input := validateCredentialInput{
		Secret:     secret,
		Components: components,
		Captures:   captures,
	}
	if err := validateCredentialInputValues(input); err != nil {
		return validateCredentialInput{}, err
	}
	return input, nil
}

func decodeValidateCredentialInput(data []byte) (validateCredentialInput, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input validateCredentialInput
	if err := decoder.Decode(&input); err != nil {
		return validateCredentialInput{}, fmt.Errorf("decoding credential JSON from stdin: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return validateCredentialInput{}, errors.New("credential stdin must contain exactly one JSON object")
		}
		return validateCredentialInput{}, fmt.Errorf("decoding credential JSON from stdin: %w", err)
	}
	if err := validateCredentialInputValues(input); err != nil {
		return validateCredentialInput{}, err
	}
	return input, nil
}

func validateCredentialInputIsJSON(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func validateStdinAvailable(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return true
	}
	info, err := file.Stat()
	return err != nil || info.Mode()&os.ModeCharDevice == 0
}

func validateCredentialInputValues(input validateCredentialInput) error {
	if input.Secret == "" {
		return errors.New("secret must not be empty")
	}
	if len(input.Secret) > maxValidateCredentialInputBytes {
		return fmt.Errorf("secret exceeds %d bytes", maxValidateCredentialInputBytes)
	}
	for ruleID, secret := range input.Components {
		if strings.TrimSpace(ruleID) == "" {
			return errors.New("component rule id must not be empty")
		}
		if ruleID != strings.TrimSpace(ruleID) {
			return fmt.Errorf("component rule id %q has surrounding whitespace", ruleID)
		}
		if secret == "" {
			return fmt.Errorf("component %q has an empty secret", ruleID)
		}
		if len(secret) > maxValidateCredentialInputBytes {
			return fmt.Errorf("component %q exceeds %d bytes", ruleID, maxValidateCredentialInputBytes)
		}
	}
	for name := range input.Captures {
		if name == "" {
			return errors.New("capture name must not be empty")
		}
	}
	return nil
}

func validateSecretFromBytes(data []byte) (string, error) {
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		return "", errors.New("secret must not be empty")
	}
	if len(secret) > maxValidateCredentialInputBytes {
		return "", fmt.Errorf("secret exceeds %d bytes", maxValidateCredentialInputBytes)
	}
	return secret, nil
}

func readLimitedValidateStdin(cmd *cobra.Command) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxValidateCredentialInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading credential from stdin: %w", err)
	}
	if len(data) > maxValidateCredentialInputBytes {
		return nil, fmt.Errorf("credential input from stdin exceeds %d bytes", maxValidateCredentialInputBytes)
	}
	return data, nil
}

func configureCredentialRuntime(cmd *cobra.Command, rt *exprruntime.Runtime) error {
	allowedEnv, err := cmd.Flags().GetStringSlice("validation-env-vars")
	if err != nil {
		return err
	}
	rt.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(allowedEnv)

	timeout, err := cmd.Flags().GetDuration("validation-timeout")
	if err != nil {
		return err
	}
	if timeout < 0 {
		return errors.New("--validation-timeout must be non-negative")
	}
	if timeout > 0 {
		rt.SetHTTPClient(&http.Client{Timeout: timeout})
	}

	maxRequests, err := getValidationMaxRequests(cmd)
	if err != nil {
		return fmt.Errorf("validation maximum requests: %w", err)
	}
	rps, err := cmd.Flags().GetFloat64("validation-rps")
	if err != nil {
		return err
	}
	if err := validateValidationRPS(rps); err != nil {
		return fmt.Errorf("--validation-rps: %w", err)
	}
	ruleRPSValues, err := cmd.Flags().GetStringSlice("validation-rps-rule")
	if err != nil {
		return err
	}
	ruleRPS, err := parseValidationRuleRPS(ruleRPSValues)
	if err != nil {
		return fmt.Errorf("--validation-rps-rule: %w", err)
	}
	if err := rt.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
		MaxRequestsPerTarget:    maxRequests,
		RequestsPerSecond:       rps,
		RequestsPerSecondByRule: ruleRPS,
	}); err != nil {
		return err
	}
	return nil
}

func evaluateCredential(
	ctx context.Context,
	rt *exprruntime.Runtime,
	program exprruntime.Program,
	finding report.Finding,
	debug bool,
) (report.Finding, error) {
	if err := ctx.Err(); err != nil {
		return report.Finding{}, err
	}

	var (
		result  report.Finding
		emitted bool
	)
	pool := validatepkg.NewPoolContext(ctx, 1, rt)
	pool.Debug = debug
	pool.Emit = func(f report.Finding) {
		result = f
		emitted = true
	}
	if err := pool.SubmitContext(ctx, finding, program); err != nil {
		pool.Close()
		return report.Finding{}, err
	}
	pool.Close()

	if err := ctx.Err(); err != nil {
		return report.Finding{}, err
	}
	if !emitted {
		return report.Finding{}, errors.New("validation did not produce a result")
	}
	return result, nil
}

func buildValidateFinding(rule configpkg.Rule, input validateCredentialInput) (report.Finding, []string, error) {
	captures := input.Captures
	attrs := map[string]string{sources.AttrPath: "betterleaks://validate"}

	components, supplied, componentSecrets := buildValidateComponents(input.Components, captures)
	if err := validateRequiredComponents(rule, supplied); err != nil {
		return report.Finding{}, nil, err
	}
	if err := validateComponentCaptures(captures, supplied); err != nil {
		return report.Finding{}, nil, err
	}

	finding := report.Finding{
		RuleID:          rule.RuleID,
		Description:     rule.Description,
		StartLine:       1,
		EndLine:         1,
		StartColumn:     1,
		Match:           input.Secret,
		Secret:          input.Secret,
		Line:            input.Secret,
		CaptureGroups:   captures,
		RuleSpecificity: rule.Specificity,
		Tags:            append([]string(nil), rule.Tags...),
	}
	finding.SetAttributes(attrs)
	if len(components) > 0 {
		finding.RequiredSets = []report.RequiredSet{{Components: components}}
	}
	finding.SetFingerprint()

	suppliedSecrets := make([]string, 0, len(componentSecrets)+1)
	suppliedSecrets = append(suppliedSecrets, input.Secret)
	suppliedSecrets = append(suppliedSecrets, componentSecrets...)
	return finding, suppliedSecrets, nil
}

func parseUniqueAssignments(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(values))
	for _, value := range values {
		key, assignment, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("%q must be in name=value form", value)
		}
		if key == "" {
			return nil, fmt.Errorf("%q has an empty name", value)
		}
		if _, exists := out[key]; exists {
			return nil, fmt.Errorf("%q is supplied more than once", key)
		}
		out[key] = assignment
	}
	return out, nil
}

func parseValidateComponentAssignments(values []string) (map[string]string, error) {
	components, err := parseUniqueAssignments(values)
	if err != nil {
		return nil, fmt.Errorf("invalid --component value: %w", err)
	}
	for rawRuleID, secret := range components {
		ruleID := strings.TrimSpace(rawRuleID)
		if ruleID == "" {
			return nil, fmt.Errorf("invalid --component rule id %q", rawRuleID)
		}
		if ruleID != rawRuleID {
			return nil, fmt.Errorf("component rule id %q has surrounding whitespace", rawRuleID)
		}
		if secret == "" {
			return nil, fmt.Errorf("component %q has an empty secret", ruleID)
		}
	}
	return components, nil
}

func buildValidateComponents(
	values map[string]string,
	captures map[string]string,
) ([]*report.RequiredFinding, map[string]struct{}, []string) {
	components := make([]*report.RequiredFinding, 0, len(values))
	supplied := make(map[string]struct{}, len(values))
	secrets := make([]string, 0, len(values))
	ruleIDs := make([]string, 0, len(values))
	for ruleID := range values {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		secret := values[ruleID]
		supplied[ruleID] = struct{}{}
		secrets = append(secrets, secret)
		components = append(components, &report.RequiredFinding{
			RuleID:        ruleID,
			StartLine:     1,
			EndLine:       1,
			StartColumn:   1,
			Secret:        secret,
			Match:         secret,
			Line:          secret,
			CaptureGroups: componentCaptureGroups(ruleID, captures),
		})
	}
	return components, supplied, secrets
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

func validateComponentCaptures(captures map[string]string, supplied map[string]struct{}) error {
	for name := range captures {
		ruleID, captureName, componentCapture := strings.Cut(name, ":")
		if !componentCapture {
			continue
		}
		if ruleID == "" || captureName == "" {
			return fmt.Errorf("capture %q must be in rule-id:name form", name)
		}
		if _, ok := supplied[ruleID]; !ok {
			return fmt.Errorf("capture %q belongs to component %q, which was not supplied", name, ruleID)
		}
	}
	return nil
}

func validateRequiredComponents(rule configpkg.Rule, supplied map[string]struct{}) error {
	required := make(map[string]struct{}, len(rule.RequiredRules))
	for _, requirement := range rule.RequiredRules {
		required[requirement.RuleID] = struct{}{}
	}

	var missing []string
	for ruleID := range required {
		if _, ok := supplied[ruleID]; !ok {
			missing = append(missing, ruleID)
		}
	}
	var extra []string
	for ruleID := range supplied {
		if _, ok := required[ruleID]; !ok {
			extra = append(extra, ruleID)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	var problems []string
	if len(missing) > 0 {
		problems = append(problems, "missing required component(s): "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		problems = append(problems, fmt.Sprintf(
			"component(s) not required by rule %q: %s",
			rule.RuleID,
			strings.Join(extra, ", "),
		))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func unknownValidationRuleError(cfg *configpkg.Config, ruleID string) error {
	query := strings.ToLower(ruleID)
	var matches []string
	seen := make(map[string]struct{}, len(cfg.Rules))
	for _, id := range sortedRuleIDs(cfg) {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		rule := cfg.Rules[id]
		if strings.TrimSpace(rule.ValidateExpr) != "" && strings.Contains(strings.ToLower(id), query) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("rule %q not found in config (use --list to see rules with validation)", ruleID)
	}
	const maxSuggestions = 8
	if len(matches) > maxSuggestions {
		matches = matches[:maxSuggestions]
	}
	return fmt.Errorf("rule %q not found; matching rules with validation: %s", ruleID, strings.Join(matches, ", "))
}
