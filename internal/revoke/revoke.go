// Package revoke executes credential revocation for the explicit CLI command.
// It is independent of the scan pipeline and never runs validation or analysis.
package revoke

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
)

// Run evaluates exactly one supplied credential combination with a fresh request
// budget. It has no result cache, worker queue, or automatic follow-up checks.
func Run(ctx context.Context, cfg *config.Config, input credential.Input, options provider.RuntimeOptions) (report.CredentialReport, error) {
	if ctx == nil {
		return report.CredentialReport{}, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	if err := cfg.Validate(); err != nil {
		return report.CredentialReport{}, fmt.Errorf("invalid config: %w", err)
	}
	rule, ok := cfg.Rule(input.RuleID)
	if !ok {
		return report.CredentialReport{}, fmt.Errorf("rule %q not found in config", input.RuleID)
	}
	if strings.TrimSpace(rule.RevokeExpr) == "" {
		return report.CredentialReport{}, fmt.Errorf("rule %q does not define revocation", rule.ID)
	}
	runtime, err := provider.NewRuntime(options)
	if err != nil {
		return report.CredentialReport{}, err
	}
	program, err := runtime.CompileRevocation(rule.RevokeExpr)
	if err != nil {
		return report.CredentialReport{}, fmt.Errorf("compiling rule %s revocation: %w", rule.ID, err)
	}
	rules := make(map[string]config.Rule, len(cfg.Rules))
	primaryCaptures := make(map[string]string, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		rules[rule.ID] = rule
		primaryCaptures[rule.ID] = credential.PrimaryCapture(rule)
	}
	finding := input.Finding(rule)
	requirements := credential.RequirementsFor(rule, primaryCaptures, rule.RevokeExpr)
	if err := credential.ValidateFinding(&finding, rule, requirements, rules, primaryCaptures); err != nil {
		return report.CredentialReport{}, err
	}
	components := make(map[string]any, len(input.Components))
	if len(finding.ComponentSets) > 0 {
		for _, component := range finding.ComponentSets[0].Components {
			components[component.RuleID] = map[string]any{"secret": component.Match.Value, "captures": component.Match.Captures}
		}
	}
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	result, evalErr := runtime.EvalRevocationWithComponents(ctx, program,
		map[string]string{"rule_id": rule.ID, "secret": finding.Match.Value}, finding.Match.Captures, components,
		exprruntime.EvalOptions{Debug: options.Debug})
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	var outcome report.Analysis
	switch {
	case result.RequestLimitHit != nil:
		hit := result.RequestLimitHit
		outcome = report.Analysis{Status: report.ValidationStatusUnknown,
			StatusReason: fmt.Sprintf("revocation request limit reached for %s after %d requests; revocation is unconfirmed", hit.Target, hit.RequestsSent)}
	case evalErr != nil:
		status := report.ValidationStatusError
		var transportError *url.Error
		if errors.As(evalErr, &transportError) {
			status = report.ValidationStatusUnknown
		}
		outcome = report.Analysis{Status: status, StatusReason: "revocation is unconfirmed: " + evalErr.Error()}
	default:
		outcome = parseResult(result.Value)
	}
	if len(result.Debug) > 0 {
		outcome.Debug = map[string]any{"revocation": result.Debug}
	}
	finding.Analysis = outcome
	for i := range finding.ComponentSets {
		finding.ComponentSets[i].Analysis = outcome
	}
	return report.NewCredentialReport(finding, finding.CredentialValues()), nil
}
