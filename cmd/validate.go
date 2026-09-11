package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
	validatepkg "github.com/betterleaks/betterleaks/v2/internal/validate"
	"github.com/betterleaks/betterleaks/v2/report"
)

const maxValidateCredentialInputBytes = 1 << 20

type ValidateCmd struct {
	ProviderRuntimeFlags `embed:""`
	RuleID               string   `name:"rule-id" help:"Rule whose validation expression should validate the secret."`
	Component            []string `sep:"none" help:"Credential component as rule-id=secret (repeatable)."`
	Capture              []string `sep:"none" help:"Validation capture as name=value; use rule-id:name=value for a component (repeatable)."`
	List                 bool     `help:"List rules that support direct validation."`
	Simple               bool     `help:"Print only the validation status."`
	JSONL                bool     `name:"jsonl" help:"Print the validation result as JSONL."`
	Secret               string   `arg:"" optional:"" help:"Secret to validate; read from stdin when omitted."`
}

func (*ValidateCmd) Help() string {
	return "When the secret is omitted, it is read from piped or redirected stdin. Supply multipart credential components explicitly with --component."
}

func (cmd *ValidateCmd) Run(cli *CLI, runtime *commandRuntime) error {
	return runValidate(runtime, &cli.GlobalFlags, cmd)
}

func runValidate(runtime *commandRuntime, globals *GlobalFlags, options *ValidateCmd) error {
	format := credentialReportFormat(options)
	if options.Simple && format != report.CredentialReportFormatPretty {
		return errors.New("--simple cannot be combined with --jsonl")
	}

	if options.List {
		if err := validateListMode(options); err != nil {
			return err
		}
		resolved, err := resolveConfig(runtime, globals.Config, "")
		if err != nil {
			return err
		}
		return writeCredentialRuleList(runtime, globals, options, newCredentialRuleList(resolved.cfg))
	}

	ruleID := strings.TrimSpace(options.RuleID)
	if ruleID == "" {
		return errors.New("--rule-id is required (use --list to see rules with validation)")
	}

	input, err := readValidateCredentialInput(runtime.stdin, options)
	if err != nil {
		return err
	}

	resolved, err := resolveConfig(runtime, globals.Config, "")
	if err != nil {
		return err
	}
	rule, ok := resolved.cfg.Rule(ruleID)
	if !ok {
		return unknownValidationRuleError(resolved.cfg, ruleID)
	}
	if strings.TrimSpace(rule.ValidateExpr) == "" {
		return fmt.Errorf("rule %q does not define validation", ruleID)
	}
	rates, err := parseProviderRuleRPS(options.ProviderRPSRule)
	if err != nil {
		return err
	}
	detector, err := detect.NewDetector(resolved.cfg, detect.WithValidation(detect.ProviderOptions{
		Workers:                 1,
		Timeout:                 options.ProviderTimeout,
		MaxRequestsPerTarget:    options.ProviderMaxRequests,
		RequestsPerSecond:       options.ProviderRPS,
		RequestsPerSecondByRule: rates,
		EnvVars:                 options.ProviderEnvVars,
	}))
	if err != nil {
		return err
	}
	credential, err := input.credential(ruleID)
	if err != nil {
		return err
	}
	result, err := detector.ValidateCredential(runtime.Context, credential)
	if err != nil {
		return err
	}

	return writeCredentialReport(runtime, globals, options, result)
}

func validateListMode(cmd *ValidateCmd) error {
	if cmd.Secret != "" {
		return errors.New("--list does not accept a secret")
	}
	if cmd.RuleID != "" {
		return errors.New("--list cannot be combined with --rule-id")
	}
	if len(cmd.Component) > 0 {
		return errors.New("--list cannot be combined with --component")
	}
	if len(cmd.Capture) > 0 {
		return errors.New("--list cannot be combined with --capture")
	}
	if cmd.Simple {
		return errors.New("--list cannot be combined with --simple")
	}
	return nil
}

func credentialReportFormat(cmd *ValidateCmd) report.CredentialReportFormat {
	if cmd.JSONL {
		return report.CredentialReportFormatJSONL
	}
	return report.CredentialReportFormatPretty
}

func credentialReporter(globals *GlobalFlags, cmd *ValidateCmd) report.CredentialReporter {
	return report.CredentialReporter{
		Format:  credentialReportFormat(cmd),
		NoColor: globals.NoColor,
		Simple:  cmd.Simple,
	}
}

func writeCredentialReport(runtime *commandRuntime, globals *GlobalFlags, cmd *ValidateCmd, result report.CredentialReport) error {
	return credentialReporter(globals, cmd).Write(runtime.stdout, result)
}

func writeCredentialRuleList(runtime *commandRuntime, globals *GlobalFlags, cmd *ValidateCmd, result report.CredentialRuleList) error {
	return credentialReporter(globals, cmd).WriteRuleList(runtime.stdout, result)
}

func newCredentialRuleList(cfg *configpkg.Config) report.CredentialRuleList {
	result := report.CredentialRuleList{SchemaVersion: report.CredentialReportSchemaVersion}
	for _, rule := range cfg.Rules {
		if strings.TrimSpace(rule.ValidateExpr) == "" {
			continue
		}
		summary := report.CredentialRuleSummary{
			RuleID:      rule.ID,
			Description: rule.Description,
			Captures:    validatepkg.RequiredCaptures(rule),
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

type validateCredentialInput struct {
	Secret     string
	Components map[string]string
	Captures   map[string]string
}

// credential translates CLI component capture names (rule-id:name) into the
// SDK's structured component inputs, keeping primary and companion captures separate.
func (input validateCredentialInput) credential(ruleID string) (detect.Credential, error) {
	supplied := make(map[string]struct{}, len(input.Components))
	components := make(map[string]detect.CredentialComponent, len(input.Components))
	for id, secret := range input.Components {
		supplied[id] = struct{}{}
		captures := make(map[string]string)
		for name, value := range input.Captures {
			if name, ok := strings.CutPrefix(name, id+":"); ok {
				captures[name] = value
			}
		}
		components[id] = detect.CredentialComponent{Secret: secret, Captures: captures}
	}
	if err := validateComponentCaptures(input.Captures, supplied); err != nil {
		return detect.Credential{}, err
	}
	primaryCaptures := make(map[string]string)
	for name, value := range input.Captures {
		if !strings.Contains(name, ":") {
			primaryCaptures[name] = value
		}
	}
	return detect.Credential{RuleID: ruleID, Secret: input.Secret, Captures: primaryCaptures, Components: components}, nil
}

func readValidateCredentialInput(stdin io.Reader, cmd *ValidateCmd) (validateCredentialInput, error) {
	var secret string
	if cmd.Secret == "" {
		if !validateStdinAvailable(stdin) {
			return validateCredentialInput{}, errors.New("secret argument or piped credential is required")
		}
		data, err := readLimitedValidateStdin(stdin)
		if err != nil {
			return validateCredentialInput{}, err
		}
		secret, err = validateSecretFromBytes(data)
		if err != nil {
			return validateCredentialInput{}, err
		}
	} else {
		var err error
		secret, err = validateSecretFromBytes([]byte(cmd.Secret))
		if err != nil {
			return validateCredentialInput{}, err
		}
	}
	captures, err := parseUniqueAssignments(cmd.Capture)
	if err != nil {
		return validateCredentialInput{}, fmt.Errorf("invalid --capture value: %w", err)
	}
	components, err := parseValidateComponentAssignments(cmd.Component)
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

func readLimitedValidateStdin(stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, maxValidateCredentialInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading credential from stdin: %w", err)
	}
	if len(data) > maxValidateCredentialInputBytes {
		return nil, fmt.Errorf("credential input from stdin exceeds %d bytes", maxValidateCredentialInputBytes)
	}
	return data, nil
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

func unknownValidationRuleError(cfg *configpkg.Config, ruleID string) error {
	query := strings.ToLower(ruleID)
	var matches []string
	for _, rule := range cfg.Rules {
		id := rule.ID
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
