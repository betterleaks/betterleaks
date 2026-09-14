package analyze

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Credential is an already-extracted secret and the inputs needed by its rule's
// provider programs. Secret is passed verbatim: it is not matched against the
// detection regex, decoded, or trimmed. Additional captures are supplied explicitly.
// Primary and component secrets must each contain between 1 byte and 1 MiB.
// Provider expressions read Secret as finding.secret and Captures as
// finding.captures. Components are exposed as components[ruleID], with the
// same secret and captures fields for each component.
type Credential struct {
	RuleID   string
	Secret   string
	Captures map[string]string
	// Components contains one credential combination, keyed by component rule ID.
	Components map[string]CredentialComponent
	// Attributes are report metadata only; provider expressions cannot read them.
	Attributes map[string]string
}

// CredentialComponent supplies a component value and its named captures.
type CredentialComponent struct {
	Secret   string
	Captures map[string]string
}

// ValidateCredential checks an already-extracted credential without running
// analysis. It bypasses discovery and scan policy. Supplied secret material is
// sanitized in the returned report. Each call has independent request limits.
func (a *Analyzer) ValidateCredential(ctx context.Context, credential Credential) (report.CredentialReport, error) {
	return a.resolveCredential(ctx, credential, false)
}

// AnalyzeCredential validates a credential, then resolves its identity and
// permissions when valid. Validation's private output is available to analysis
// but never exported in the report. Calls may run concurrently.
func (a *Analyzer) AnalyzeCredential(ctx context.Context, credential Credential) (report.CredentialReport, error) {
	return a.resolveCredential(ctx, credential, true)
}

func (a *Analyzer) resolveCredential(ctx context.Context, credential Credential, analysis bool) (report.CredentialReport, error) {
	if ctx == nil {
		return report.CredentialReport{}, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	if a == nil || a.runtime == nil {
		return report.CredentialReport{}, errors.New("analyzer must be constructed with New")
	}
	rule, ok := a.rules[credential.RuleID]
	if !ok {
		return report.CredentialReport{}, fmt.Errorf("rule %q not found in config", credential.RuleID)
	}
	if strings.TrimSpace(rule.ValidateExpr) == "" {
		return report.CredentialReport{}, fmt.Errorf("rule %q does not define validation", credential.RuleID)
	}
	finding := credentialFinding(rule, credential)
	secrets := finding.CredentialValues()
	result, err := a.resolve(ctx, finding, analysis)
	if err != nil {
		return report.CredentialReport{}, err
	}
	return report.NewCredentialReport(result, secrets), nil
}

func credentialFinding(rule config.Rule, input Credential) report.Finding {
	optional := make(map[string]bool, len(rule.Components))
	for _, c := range rule.Components {
		optional[c.RuleID] = c.Optional
	}

	attrs := maps.Clone(input.Attributes)
	if attrs == nil {
		attrs = make(map[string]string)
	}
	if _, ok := attrs[sources.AttrPath]; !ok {
		attrs[sources.AttrPath] = "betterleaks://validate"
	}
	finding := report.Finding{
		RuleID:          rule.ID,
		Description:     rule.Description,
		Match:           report.Match{Full: input.Secret, Value: input.Secret, Captures: maps.Clone(input.Captures)},
		Line:            input.Secret,
		RuleSpecificity: rule.Specificity,
		Tags:            slices.Clone(rule.Tags),
		Location:        report.Location{StartLine: 1, EndLine: 1, StartColumn: 1},
	}
	finding.SetAttributes(attrs)
	components := make([]*report.ComponentFinding, 0, len(input.Components))
	for _, id := range slices.Sorted(maps.Keys(input.Components)) {
		component := input.Components[id]
		components = append(components, &report.ComponentFinding{
			RuleID:   id,
			Optional: optional[id],
			Match:    report.Match{Full: component.Secret, Value: component.Secret, Captures: maps.Clone(component.Captures)},
			Line:     component.Secret,
			Location: report.Location{StartLine: 1, EndLine: 1, StartColumn: 1},
		})
	}
	if len(components) > 0 {
		finding.ComponentSets = []report.ComponentSet{{Components: components}}
	}
	return finding
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
