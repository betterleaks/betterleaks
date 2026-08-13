package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/internal/confidence"
	"github.com/betterleaks/betterleaks/internal/contextwindow"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/regexp"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	// RuleID is a unique identifier for this rule
	RuleID string

	// Description is the description of the rule.
	Description string

	// Entropy is a float representing the minimum shannon
	// entropy a regex group must have to be considered a secret.
	Entropy float64

	// SecretGroup is an int used to extract secret from regex
	// match and used as the group that will have its entropy
	// checked if `entropy` is set.
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

	// Allowlists allows a rule to be ignored for specific commits, paths, regexes, and/or stopwords.
	Allowlists []*Allowlist

	// validated is an internal flag to track whether `Validate()` has been called.
	validated bool

	// Components are other rules whose matches contribute to this rule.
	// Required components gate the rule; optional components are attached when found.
	Components []*Component

	// componentsSet records whether a config explicitly supplied components. It is
	// used while extending configs to distinguish omission from components = [].
	componentsSet bool

	SkipReport bool

	// TokenEfficiency enables the Token Efficiency filter for this rule.
	// When enabled, candidate secrets are evaluated using BPE tokenization
	// to measure how "rare" or non-natural-language a string is. Strings that
	// tokenize efficiently (i.e., common words/phrases) are filtered out.
	TokenEfficiency bool

	// ValidateExpr is the raw expression used for secret validation.
	ValidateExpr string

	// validationProgram is the compiled validation program, set at config load time.
	validationProgram exprruntime.Program

	// Filter is an expression evaluated against attributes + finding per regex match.
	// Returns true = skip (discard this finding); false = keep.
	// Deprecated legacy Allowlists, Entropy, and TokenEfficiency are translated into this field.
	Filter string

	// filterProgram is the compiled filter program, set at startup.
	filterProgram exprruntime.Program
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
	if r.validated {
		return nil
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
	if r.Regex != nil && r.SecretGroup > r.Regex.NumSubexp() {
		return fmt.Errorf("%s: invalid regex secret group %d, max regex secret group %d", r.RuleID, r.SecretGroup, r.Regex.NumSubexp())
	}

	for _, allowlist := range r.Allowlists {
		// This will probably never happen.
		if allowlist == nil {
			continue
		}
		if err := allowlist.Validate(); err != nil {
			return fmt.Errorf("%s: %w", r.RuleID, err)
		}
	}

	seenComponents := make(map[string]struct{}, len(r.Components))
	for _, component := range r.Components {
		if component == nil {
			return fmt.Errorf("%s: component is nil", r.RuleID)
		}
		if strings.TrimSpace(component.RuleID) == "" {
			return fmt.Errorf("%s: component rule ID is empty", r.RuleID)
		}
		if _, exists := seenComponents[component.RuleID]; exists {
			return fmt.Errorf("%s: duplicate component rule ID %q", r.RuleID, component.RuleID)
		}
		seenComponents[component.RuleID] = struct{}{}
		if _, err := contextwindow.Parse(component.Within); err != nil {
			return fmt.Errorf("%s: component %q has invalid within value %q: %w", r.RuleID, component.RuleID, component.Within, err)
		}
	}

	r.validated = true
	return nil
}

// ValidationProgram returns the compiled validation program for this rule, or nil.
func (r *Rule) ValidationProgram() exprruntime.Program {
	return r.validationProgram
}

// SetValidationProgram stores a compiled validation program on the rule.
func (r *Rule) SetValidationProgram(p exprruntime.Program) {
	r.validationProgram = p
}

// FilterProgram returns the compiled filter program for this rule, or nil.
func (r *Rule) FilterProgram() exprruntime.Program { return r.filterProgram }

// SetFilterProgram stores a compiled filter program on the rule.
func (r *Rule) SetFilterProgram(p exprruntime.Program) { r.filterProgram = p }
