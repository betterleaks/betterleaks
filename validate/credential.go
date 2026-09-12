package validate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Credential is an already-extracted secret and the inputs needed by its rule's
// provider programs. Secret is passed verbatim: it is not matched against the
// detection regex, decoded, or trimmed. Captures must be supplied explicitly.
// Primary and component secrets must each contain between 1 byte and 1 MiB.
// Provider expressions read Secret as finding.secret and Captures as
// finding.captures. Components are exposed as components[ruleID], with the
// same secret and captures fields for each companion.
type Credential struct {
	RuleID   string
	Secret   string
	Captures map[string]string
	// Components contains one credential combination, keyed by component rule ID.
	Components map[string]CredentialComponent
	// Attributes are available to provider expressions. A missing path defaults
	// to betterleaks://validate, as it does for the validate command.
	Attributes map[string]string
}

// CredentialComponent supplies a companion secret and its named captures.
type CredentialComponent struct {
	Secret   string
	Captures map[string]string
}

// ValidateCredential validates an already-extracted credential and optionally
// analyzes it. It bypasses detection, decoding, and scan filters. Missing
// analysis leaves Analysis empty. Invalid input, compilation failures, and
// cancellation return Go errors. Provider failures appear in Validation.Status
// and Analysis.Reason. Supplied credential values are sanitized in reports.
//
// Calls may run concurrently. Each call owns its runtime, cache, and request
// limits; limits are not shared between calls. Input maps are copied; callers
// must not mutate them during the call.
func (v *Validator) ValidateCredential(ctx context.Context, credential Credential) (report.CredentialReport, error) {
	if ctx == nil {
		return report.CredentialReport{}, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	if v == nil || v.runtime == nil {
		return report.CredentialReport{}, errors.New("validator must be constructed with NewValidator")
	}
	rule, ok := v.rules[credential.RuleID]
	if !ok {
		return report.CredentialReport{}, fmt.Errorf("rule %q not found in config", credential.RuleID)
	}
	if strings.TrimSpace(rule.ValidateExpr) == "" {
		return report.CredentialReport{}, fmt.Errorf("rule %q does not define validation", credential.RuleID)
	}
	expressions := []string{rule.ValidateExpr}
	if v.options.Analysis {
		expressions = append(expressions, rule.AnalyzeExpr)
	}
	finding, secrets, err := credentialFinding(rule, credential, expressions)
	if err != nil {
		return report.CredentialReport{}, err
	}
	programs, err := v.programsFor(rule)
	if err != nil {
		return report.CredentialReport{}, err
	}
	// Each direct call uses one worker and a fresh provider runtime.
	pool, err := provider.NewConfiguredPool(ctx, 1, v.options.runtimeOptions())
	if err != nil {
		return report.CredentialReport{}, err
	}
	var result report.Finding
	emitted := false
	pool.Emit = func(f report.Finding) {
		result = f
		emitted = true
	}
	submitErr := pool.SubmitWithAnalysisContext(ctx, finding, programs.validation, programs.analysis)
	pool.Close() // Wait for evaluation and synchronize access to result.
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	if submitErr != nil {
		return report.CredentialReport{}, submitErr
	}
	if !emitted {
		return report.CredentialReport{}, errors.New("validation did not produce a result")
	}
	return report.NewCredentialReport(result, secrets), nil
}

func credentialFinding(rule config.Rule, input Credential, expressions []string) (report.Finding, []string, error) {
	if err := validateCredentialSecret("secret", input.Secret); err != nil {
		return report.Finding{}, nil, err
	}
	if err := validateCredentialCaptures(input.Captures); err != nil {
		return report.Finding{}, nil, err
	}
	var missingCaptures []string
	for _, name := range provider.RequiredCaptures(rule, expressions...) {
		if input.Captures[name] == "" {
			missingCaptures = append(missingCaptures, name)
		}
	}
	if len(missingCaptures) > 0 {
		return report.Finding{}, nil, fmt.Errorf("missing required capture(s) for rule %q: %s", rule.ID, strings.Join(missingCaptures, ", "))
	}
	optional := make(map[string]bool, len(rule.Components))
	var missing, extra []string
	for _, component := range rule.Components {
		optional[component.RuleID] = component.Optional
		if _, ok := input.Components[component.RuleID]; !ok && !component.Optional {
			missing = append(missing, component.RuleID)
		}
	}
	for id := range input.Components {
		if _, ok := optional[id]; !ok {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	var problems []string
	if len(missing) > 0 {
		problems = append(problems, "missing required component(s): "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		problems = append(problems, fmt.Sprintf("component(s) not declared by rule %q: %s", rule.ID, strings.Join(extra, ", ")))
	}
	if len(problems) > 0 {
		return report.Finding{}, nil, errors.New(strings.Join(problems, "; "))
	}

	attrs := maps.Clone(input.Attributes)
	if attrs == nil {
		attrs = make(map[string]string)
	}
	if _, ok := attrs[sources.AttrPath]; !ok {
		attrs[sources.AttrPath] = "betterleaks://validate"
	}
	finding := report.Finding{
		RuleID: rule.ID, Description: rule.Description,
		Match: input.Secret, Secret: input.Secret, Line: input.Secret,
		CaptureGroups: maps.Clone(input.Captures), RuleSpecificity: rule.Specificity,
		Tags:     slices.Clone(rule.Tags),
		Location: report.Location{StartLine: 1, EndLine: 1, StartColumn: 1},
	}
	finding.SetAttributes(attrs)
	secrets := []string{input.Secret}
	for _, value := range input.Captures {
		secrets = append(secrets, value)
	}
	components := make([]*report.ComponentFinding, 0, len(input.Components))
	for _, id := range slices.Sorted(maps.Keys(input.Components)) {
		component := input.Components[id]
		if err := validateCredentialSecret(fmt.Sprintf("component %q", id), component.Secret); err != nil {
			return report.Finding{}, nil, err
		}
		if err := validateCredentialCaptures(component.Captures); err != nil {
			return report.Finding{}, nil, fmt.Errorf("component %q: %w", id, err)
		}
		secrets = append(secrets, component.Secret)
		for _, value := range component.Captures {
			secrets = append(secrets, value)
		}
		components = append(components, &report.ComponentFinding{
			RuleID: id, Optional: optional[id], Secret: component.Secret, Match: component.Secret, Line: component.Secret,
			CaptureGroups: maps.Clone(component.Captures),
			Location:      report.Location{StartLine: 1, EndLine: 1, StartColumn: 1},
		})
	}
	if len(components) > 0 {
		finding.ComponentSets = []report.ComponentSet{{Components: components}}
	}
	return finding, secrets, nil
}

func validateCredentialSecret(label, secret string) error {
	if secret == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	const maxSecretBytes = 1 << 20
	if len(secret) > maxSecretBytes {
		return fmt.Errorf("%s exceeds %d bytes", label, maxSecretBytes)
	}
	return nil
}

func validateCredentialCaptures(captures map[string]string) error {
	for name := range captures {
		if name == "" {
			return errors.New("capture name must not be empty")
		}
	}
	return nil
}
