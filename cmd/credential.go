package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/betterleaks/betterleaks/v2/analyze"
	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/internal/revoke"
	"github.com/betterleaks/betterleaks/v2/report"
)

const maxCredentialInputBytes = 1 << 20

type credentialOperation string

const (
	credentialValidation credentialOperation = "validation"
	credentialAnalysis   credentialOperation = "analysis"
	credentialRevocation credentialOperation = "revocation"
)

func (operation credentialOperation) supported(rule configpkg.Rule) bool {
	switch operation {
	case credentialValidation:
		return strings.TrimSpace(rule.ValidateExpr) != ""
	case credentialAnalysis:
		return strings.TrimSpace(rule.ValidateExpr) != "" && strings.TrimSpace(rule.AnalyzeExpr) != ""
	case credentialRevocation:
		return strings.TrimSpace(rule.RevokeExpr) != ""
	}
	return false
}

// CredentialFlags is shared by the direct validate, analyze, and revoke commands.
type CredentialFlags struct {
	ProviderRuntimeFlags `embed:""`
	RuleID               string   `name:"rule" help:"Rule to use for this credential."`
	Component            []string `sep:"none" help:"Credential component as rule-id=secret (repeatable)."`
	Capture              []string `sep:"none" help:"Credential capture as name=value; use rule-id:name=value for a component (repeatable)."`
	Simple               bool     `help:"Print only the credential status."`
	JSONL                bool     `name:"jsonl" help:"Print the credential result as JSONL."`
	Secret               string   `arg:"" optional:"" help:"Credential value; read from stdin when omitted."`
}

func runCredential(runtime *commandRuntime, globals *GlobalFlags, options *CredentialFlags, operation credentialOperation) error {
	format := credentialReportFormat(options)
	if options.Simple && format != report.CredentialReportFormatPretty {
		return errors.New("--simple cannot be combined with --jsonl")
	}

	ruleID := strings.TrimSpace(options.RuleID)
	if ruleID == "" {
		return errors.New("--rule is required (use config show ids to see rule IDs)")
	}

	input, err := readCredentialInput(runtime.stdin, options)
	if err != nil {
		return err
	}

	resolved, err := resolveConfig(runtime, globals.Config, "")
	if err != nil {
		return err
	}
	rule, ok := resolved.cfg.Rule(ruleID)
	if !ok {
		return unknownCredentialRuleError(resolved.cfg, ruleID, operation)
	}
	if !operation.supported(rule) {
		return fmt.Errorf("rule %q does not define %s", ruleID, operation)
	}
	rates, err := parseProviderRuleRPS(options.ProviderRPSRule)
	if err != nil {
		return err
	}
	value, err := input.credential(ruleID)
	if err != nil {
		return err
	}
	if operation == credentialRevocation {
		result, err := revoke.Run(runtime.Context, resolved.cfg, value, provider.RuntimeOptions{
			Debug:                   options.ProviderDebug,
			Timeout:                 options.ProviderTimeout,
			MaxRequestsPerTarget:    options.ProviderMaxRequests,
			RequestsPerSecond:       options.ProviderRPS,
			RequestsPerSecondByRule: rates,
			EnvVars:                 options.ProviderEnvVars,
		})
		if err != nil {
			return err
		}
		return writeCredentialReport(runtime, globals, options, result)
	}
	analyzer, err := analyze.New(resolved.cfg,
		analyze.WithDebug(options.ProviderDebug),
		analyze.WithTimeout(options.ProviderTimeout),
		analyze.WithMaxRequestsPerTarget(options.ProviderMaxRequests),
		analyze.WithRequestsPerSecond(options.ProviderRPS),
		analyze.WithRequestsPerSecondByRule(rates),
		analyze.WithEnvVars(options.ProviderEnvVars...),
	)
	if err != nil {
		return err
	}
	resolve := analyzer.ValidateCredential
	if operation == credentialAnalysis {
		resolve = analyzer.AnalyzeCredential
	}
	result, err := resolve(runtime.Context, value)
	if err != nil {
		return err
	}

	return writeCredentialReport(runtime, globals, options, result)
}

func credentialReportFormat(cmd *CredentialFlags) report.CredentialReportFormat {
	if cmd.JSONL {
		return report.CredentialReportFormatJSONL
	}
	return report.CredentialReportFormatPretty
}

func credentialReporter(globals *GlobalFlags, cmd *CredentialFlags) report.CredentialReporter {
	return report.CredentialReporter{
		Format:  credentialReportFormat(cmd),
		NoColor: globals.NoColor,
		Simple:  cmd.Simple,
	}
}

func writeCredentialReport(runtime *commandRuntime, globals *GlobalFlags, cmd *CredentialFlags, result report.CredentialReport) error {
	return credentialReporter(globals, cmd).Write(runtime.stdout, result)
}

type credentialInput struct {
	Secret     string
	Components map[string]string
	Captures   map[string]string
}

// credential translates CLI component capture names (rule-id:name) into the
// SDK's structured component inputs, keeping primary and companion captures separate.
func (input credentialInput) credential(ruleID string) (credential.Input, error) {
	supplied := make(map[string]struct{}, len(input.Components))
	components := make(map[string]credential.Component, len(input.Components))
	for id, secret := range input.Components {
		supplied[id] = struct{}{}
		captures := make(map[string]string)
		for name, value := range input.Captures {
			if name, ok := strings.CutPrefix(name, id+":"); ok {
				captures[name] = value
			}
		}
		components[id] = credential.Component{Secret: secret, Captures: captures}
	}
	if err := validateComponentCaptures(input.Captures, supplied); err != nil {
		return credential.Input{}, err
	}
	primaryCaptures := make(map[string]string)
	for name, value := range input.Captures {
		if !strings.Contains(name, ":") {
			primaryCaptures[name] = value
		}
	}
	return credential.Input{RuleID: ruleID, Secret: input.Secret, Captures: primaryCaptures, Components: components}, nil
}

func readCredentialInput(stdin io.Reader, cmd *CredentialFlags) (credentialInput, error) {
	var secret string
	if cmd.Secret == "" {
		if !credentialStdinAvailable(stdin) {
			return credentialInput{}, errors.New("secret argument or piped credential is required")
		}
		data, err := readLimitedCredentialStdin(stdin)
		if err != nil {
			return credentialInput{}, err
		}
		secret, err = credentialSecretFromBytes(data)
		if err != nil {
			return credentialInput{}, err
		}
	} else {
		var err error
		secret, err = credentialSecretFromBytes([]byte(cmd.Secret))
		if err != nil {
			return credentialInput{}, err
		}
	}
	captures, err := parseUniqueAssignments(cmd.Capture)
	if err != nil {
		return credentialInput{}, fmt.Errorf("invalid --capture value: %w", err)
	}
	components, err := parseCredentialComponentAssignments(cmd.Component)
	if err != nil {
		return credentialInput{}, err
	}

	input := credentialInput{
		Secret:     secret,
		Components: components,
		Captures:   captures,
	}
	if err := validateCredentialInputValues(input); err != nil {
		return credentialInput{}, err
	}
	return input, nil
}

func credentialStdinAvailable(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return true
	}
	info, err := file.Stat()
	return err != nil || info.Mode()&os.ModeCharDevice == 0
}

func validateCredentialInputValues(input credentialInput) error {
	if input.Secret == "" {
		return errors.New("secret must not be empty")
	}
	if len(input.Secret) > maxCredentialInputBytes {
		return fmt.Errorf("secret exceeds %d bytes", maxCredentialInputBytes)
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
		if len(secret) > maxCredentialInputBytes {
			return fmt.Errorf("component %q exceeds %d bytes", ruleID, maxCredentialInputBytes)
		}
	}
	for name := range input.Captures {
		if name == "" {
			return errors.New("capture name must not be empty")
		}
	}
	return nil
}

func credentialSecretFromBytes(data []byte) (string, error) {
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		return "", errors.New("secret must not be empty")
	}
	if len(secret) > maxCredentialInputBytes {
		return "", fmt.Errorf("secret exceeds %d bytes", maxCredentialInputBytes)
	}
	return secret, nil
}

func readLimitedCredentialStdin(stdin io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(stdin, maxCredentialInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading credential from stdin: %w", err)
	}
	if len(data) > maxCredentialInputBytes {
		return nil, fmt.Errorf("credential input from stdin exceeds %d bytes", maxCredentialInputBytes)
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

func parseCredentialComponentAssignments(values []string) (map[string]string, error) {
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

func unknownCredentialRuleError(cfg *configpkg.Config, ruleID string, operation credentialOperation) error {
	query := strings.ToLower(ruleID)
	var matches []string
	for _, rule := range cfg.Rules {
		id := rule.ID
		if operation.supported(rule) && strings.Contains(strings.ToLower(id), query) {
			matches = append(matches, id)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("rule %q not found in config (use config show ids --%s to see supported rules)", ruleID, operation)
	}
	const maxSuggestions = 8
	if len(matches) > maxSuggestions {
		matches = matches[:maxSuggestions]
	}
	return fmt.Errorf("rule %q not found; matching rules with %s: %s", ruleID, operation, strings.Join(matches, ", "))
}
