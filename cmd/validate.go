package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/expr-lang/expr/ast"
	exprparser "github.com/expr-lang/expr/parser"
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
		Long:         "Validate a known secret without running detection.\n\nWhen [secret] is omitted, the primary secret is read from piped or redirected stdin automatically. Supply multipart credential components explicitly with --component.",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE:         runValidate,
	}
	cmd.Flags().String("rule-id", "", "rule whose validation expression should validate the secret")
	cmd.Flags().StringArray("component", nil, "credential component as rule-id=secret (repeatable)")
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
	debug, err := cmd.Flags().GetBool("validation-debug")
	if err != nil {
		return err
	}
	if debug {
		return errors.New("--validation-debug is not supported by validate because debug request and response bodies may contain credentials")
	}
	simple, err := cmd.Flags().GetBool("simple")
	if err != nil {
		return err
	}
	if simple && format != report.CredentialReportFormatPretty {
		return errors.New("--simple cannot be combined with --report-format=jsonl")
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
	if err := validateRequiredCaptures(rule, input.Captures); err != nil {
		return err
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

	validated, err := evaluateCredential(cmd.Context(), rt, program, finding)
	if err != nil {
		return err
	}

	includeEmpty, err := cmd.Flags().GetBool("validation-extract-empty")
	if err != nil {
		return err
	}
	result := report.NewCredentialReport(validated, suppliedSecrets, includeEmpty)
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

func credentialReportFormat(cmd *cobra.Command) (report.CredentialReportFormat, error) {
	path, err := cmd.Flags().GetString("report-path")
	if err != nil {
		return "", err
	}
	if path != "" {
		return "", errors.New("--report-path is not supported by validate; validation results are written to stdout")
	}
	templatePath, err := cmd.Flags().GetString("report-template")
	if err != nil {
		return "", err
	}
	if templatePath != "" {
		return "", errors.New("--report-template is not supported by validate; use pretty, --simple, or --report-format=jsonl")
	}
	format, err := cmd.Flags().GetString("report-format")
	if err != nil {
		return "", err
	}
	return report.ResolveCredentialReportFormat(format)
}

func credentialReporter(cmd *cobra.Command) (report.CredentialReporter, error) {
	format, err := credentialReportFormat(cmd)
	if err != nil {
		return report.CredentialReporter{}, err
	}
	noColor, err := cmd.Flags().GetBool("no-color")
	if err != nil {
		return report.CredentialReporter{}, err
	}
	simple, err := cmd.Flags().GetBool("simple")
	if err != nil {
		return report.CredentialReporter{}, err
	}
	return report.CredentialReporter{
		Format:  format,
		NoColor: noColor,
		Simple:  simple,
	}, nil
}

func writeCredentialReport(cmd *cobra.Command, result report.CredentialReport) error {
	reporter, err := credentialReporter(cmd)
	if err != nil {
		return err
	}
	return reporter.Write(cmd.OutOrStdout(), result)
}

func writeCredentialRuleList(cmd *cobra.Command, result report.CredentialRuleList) error {
	reporter, err := credentialReporter(cmd)
	if err != nil {
		return err
	}
	return reporter.WriteRuleList(cmd.OutOrStdout(), result)
}

func newCredentialRuleList(cfg *configpkg.Config) report.CredentialRuleList {
	result := report.CredentialRuleList{SchemaVersion: report.CredentialReportSchemaVersion}
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
		summary := report.CredentialRuleSummary{
			RuleID:      rule.RuleID,
			Description: rule.Description,
			Captures:    requiredValidationCaptures(rule),
		}
		for _, component := range rule.Components {
			summary.Components = append(summary.Components, report.CredentialComponentReport{
				RuleID:   component.RuleID,
				Optional: component.Optional,
			})
		}
		sort.Slice(summary.Components, func(i, j int) bool {
			return summary.Components[i].RuleID < summary.Components[j].RuleID
		})
		result.Rules = append(result.Rules, summary)
	}
	return result
}

func requiredValidationCaptures(rule configpkg.Rule) []string {
	if rule.Regex == nil {
		return nil
	}
	referenced := referencedValidationCaptures(rule.ValidateExpr)
	names := rule.Regex.SubexpNames()
	required := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for index, name := range names {
		if name == "" || index == rule.SecretGroup {
			continue
		}
		if _, ok := referenced[name]; !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		required = append(required, name)
	}
	sort.Strings(required)
	return required
}

type validationCaptureCollector map[string]struct{}

func (c validationCaptureCollector) Visit(node *ast.Node) {
	member, ok := (*node).(*ast.MemberNode)
	if !ok || !isValidationCaptureObject(member.Node) {
		return
	}
	property, ok := member.Property.(*ast.StringNode)
	if ok && property.Value != "" {
		c[property.Value] = struct{}{}
	}
}

func referencedValidationCaptures(expression string) map[string]struct{} {
	captures := validationCaptureCollector{}
	tree, err := exprparser.Parse(expression)
	if err != nil {
		return captures
	}
	ast.Walk(&tree.Node, captures)
	return captures
}

func isValidationCaptureObject(node ast.Node) bool {
	for {
		chain, ok := node.(*ast.ChainNode)
		if !ok {
			break
		}
		node = chain.Node
	}
	if identifier, ok := node.(*ast.IdentifierNode); ok {
		return identifier.Value == "captures"
	}
	member, ok := node.(*ast.MemberNode)
	if !ok {
		return false
	}
	property, ok := member.Property.(*ast.StringNode)
	if !ok || property.Value != "captures" {
		return false
	}
	base, ok := member.Node.(*ast.IdentifierNode)
	return ok && base.Value == "finding"
}

func validateRequiredCaptures(rule configpkg.Rule, supplied map[string]string) error {
	var missing []string
	for _, name := range requiredValidationCaptures(rule) {
		if supplied[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf(
		"missing required capture(s) for rule %q: %s (use --capture name=value)",
		rule.RuleID,
		strings.Join(missing, ", "),
	)
}

type validateCredentialInput struct {
	Secret     string
	Components map[string]string
	Captures   map[string]string
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
) (report.Finding, error) {
	if err := ctx.Err(); err != nil {
		return report.Finding{}, err
	}

	var (
		result  report.Finding
		emitted bool
	)
	pool := validatepkg.NewPoolContext(ctx, 1, rt)
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

	components, supplied, componentSecrets := buildValidateComponents(rule, input.Components, captures)
	if err := validateComponents(rule, supplied); err != nil {
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
		finding.ComponentSets = []report.ComponentSet{{Components: components}}
	}
	finding.SetFingerprint()

	suppliedSecrets := make([]string, 0, len(componentSecrets)+len(input.Captures)+1)
	suppliedSecrets = append(suppliedSecrets, input.Secret)
	suppliedSecrets = append(suppliedSecrets, componentSecrets...)
	for _, capture := range input.Captures {
		suppliedSecrets = append(suppliedSecrets, capture)
	}
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
	rule configpkg.Rule,
	values map[string]string,
	captures map[string]string,
) ([]*report.ComponentFinding, map[string]struct{}, []string) {
	components := make([]*report.ComponentFinding, 0, len(values))
	optional := make(map[string]bool, len(rule.Components))
	for _, component := range rule.Components {
		optional[component.RuleID] = component.Optional
	}
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
		components = append(components, &report.ComponentFinding{
			RuleID:        ruleID,
			Optional:      optional[ruleID],
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

func validateComponents(rule configpkg.Rule, supplied map[string]struct{}) error {
	declared := make(map[string]struct{}, len(rule.Components))
	required := make(map[string]struct{}, len(rule.Components))
	for _, component := range rule.Components {
		declared[component.RuleID] = struct{}{}
		if !component.Optional {
			required[component.RuleID] = struct{}{}
		}
	}

	var missing []string
	for ruleID := range required {
		if _, ok := supplied[ruleID]; !ok {
			missing = append(missing, ruleID)
		}
	}
	var extra []string
	for ruleID := range supplied {
		if _, ok := declared[ruleID]; !ok {
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
			"component(s) not declared by rule %q: %s",
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
