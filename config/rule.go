package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/internal/confidence"
	"github.com/betterleaks/betterleaks/internal/contextwindow"
	"github.com/betterleaks/betterleaks/regexp"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	// RuleID is a unique identifier for this rule
	RuleID string

	// Description is the description of the rule.
	Description string

	// SecretGroup identifies the regex group used as the secret.
	SecretGroup int

	// Regex is a golang regular expression used to detect secrets.
	Regex *regexp.Regexp

	// Path is a golang regular expression used to
	// filter secrets by path
	Path *regexp.Regexp

	// Tags is an array of strings used for metadata
	// and reporting purposes.
	Tags []string

	// Specificity controls precedence when overlapping findings compete.
	// Higher specificity findings suppress lower specificity findings.
	Specificity int

	// Confidence estimates how likely a match is to be a real secret.
	Confidence string

	// Keywords are used for pre-regex check filtering. Rules that contain
	// keywords will perform a quick string compare check to make sure the
	// keyword(s) are in the content being scanned.
	Keywords []string

	// Components are other rules whose matches contribute to this rule.
	// Required components gate the rule; optional components are attached when found.
	Components []*Component

	SkipReport bool

	// ValidateExpr is the raw expression used for secret validation.
	ValidateExpr string

	// AnalyzeExpr is the raw expression used to enrich a valid credential with
	// identity and provider-neutral capabilities.
	AnalyzeExpr string

	// Filter is an expression evaluated against attributes + finding per regex match.
	// Returns true = skip (discard this finding); false = keep.
	Filter string
}

// Component references another rule that contributes a nearby match to a multipart finding.
type Component struct {
	RuleID string
	// Optional components are attached when found but do not gate the primary finding.
	Optional bool
	// Within uses the same directional L/C grammar as --match-context.
	Within string
}

// Validate guards against common misconfigurations.
func (r *Rule) Validate() error {
	if r == nil {
		return errors.New("rule is required")
	}

	// Ensure |id| is present.
	if strings.TrimSpace(r.RuleID) == "" {
		// Try to provide helpful context, since |id| is empty.
		var sb strings.Builder
		if r.Description != "" {
			sb.WriteString(", description: " + r.Description)
		}
		if r.Regex != nil {
			sb.WriteString(", regex: " + r.Regex.String())
		}
		if r.Path != nil {
			sb.WriteString(", path: " + r.Path.String())
		}
		return errors.New("rule |id| is missing or empty" + sb.String())
	}

	// Ensure the rule actually matches something.
	if r.Regex == nil && r.Path == nil {
		return errors.New(r.RuleID + ": both |regex| and |path| are empty, this rule will have no effect")
	}
	if r.Confidence != "" && !confidence.Valid(r.Confidence) {
		return fmt.Errorf("%s: invalid confidence %q (expected low, medium, or high)", r.RuleID, r.Confidence)
	}

	// Ensure |secretGroup| works.
	if r.SecretGroup < 0 {
		return fmt.Errorf("%s: invalid regex secret group %d, must be non-negative", r.RuleID, r.SecretGroup)
	}
	if r.Regex == nil && r.SecretGroup != 0 {
		return fmt.Errorf("%s: regex secret group %d requires a regex", r.RuleID, r.SecretGroup)
	}
	if r.Regex != nil && r.SecretGroup > r.Regex.NumSubexp() {
		return fmt.Errorf("%s: invalid regex secret group %d, max regex secret group %d", r.RuleID, r.SecretGroup, r.Regex.NumSubexp())
	}
	if strings.TrimSpace(r.AnalyzeExpr) != "" && strings.TrimSpace(r.ValidateExpr) == "" {
		return fmt.Errorf("%s: analyze expression requires a validate expression", r.RuleID)
	}

	seenComponents := make(map[string]struct{}, len(r.Components))
	for _, component := range r.Components {
		if component == nil {
			return fmt.Errorf("%s: component is nil", r.RuleID)
		}
		if strings.TrimSpace(component.RuleID) == "" {
			return fmt.Errorf("%s: component rule ID is empty", r.RuleID)
		}
		if component.RuleID == r.RuleID {
			return fmt.Errorf("%s: rule cannot reference itself as a component", r.RuleID)
		}
		if _, exists := seenComponents[component.RuleID]; exists {
			return fmt.Errorf("%s: duplicate component rule ID %q", r.RuleID, component.RuleID)
		}
		seenComponents[component.RuleID] = struct{}{}
		if _, err := contextwindow.Parse(component.Within); err != nil {
			return fmt.Errorf("%s: component %q has invalid within value %q: %w", r.RuleID, component.RuleID, component.Within, err)
		}
	}

	return nil
}
