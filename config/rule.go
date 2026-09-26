package config

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	// ID is a unique identifier for this rule
	ID string

	// Description is the description of the rule.
	Description string

	// ValueGroup selects the capture group used for Match.Value.
	// Positive values are 1-based capture group indexes.
	// Zero selects the first non-empty capture group, falling back to
	// Match.Full if none exists. An explicitly selected group that
	// does not participate produces an empty value.
	ValueGroup int

	// Regex is a Go regular expression pattern used to detect secrets.
	// An empty pattern disables content matching. Scanner owns compilation.
	Regex string

	// Path is a Go regular expression pattern used to filter secrets by path.
	// An empty pattern matches any path when Regex is set.
	Path string

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
	Components []Component

	SkipReport bool

	// ValidateExpr is the raw expression used for secret validation.
	ValidateExpr string

	// AnalyzeExpr is the raw expression used to enrich a valid credential with
	// identity and provider-neutral capabilities.
	AnalyzeExpr string

	// RevokeExpr is an optional credential revocation program. It executes only
	// through the explicit revoke command, never during scanning or analysis.
	RevokeExpr string

	// FilterExpr is an expression evaluated against attributes + finding per regex match.
	// finding.captures holds this match's named groups. Components are assembled
	// after filtering. Provider expressions, including explicit revocation, read
	// supplied components independently of filtering.
	// Returns true = skip (discard this finding); false = keep.
	FilterExpr string
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
	if strings.TrimSpace(r.ID) == "" {
		// Try to provide helpful context, since |id| is empty.
		var sb strings.Builder
		if r.Description != "" {
			sb.WriteString(", description: " + r.Description)
		}
		if r.Regex != "" {
			sb.WriteString(", regex: " + r.Regex)
		}
		if r.Path != "" {
			sb.WriteString(", path: " + r.Path)
		}
		return errors.New("rule |id| is missing or empty" + sb.String())
	}

	// Ensure the rule actually matches something.
	if r.Regex == "" && r.Path == "" {
		return errors.New(r.ID + ": both |regex| and |path| are empty, this rule will have no effect")
	}
	if r.Confidence != "" && !confidence.Valid(r.Confidence) {
		return fmt.Errorf("%s: invalid confidence %q (expected low, medium, or high)", r.ID, r.Confidence)
	}

	maxCapture, err := r.validatePatterns()
	if err != nil {
		return err
	}

	if r.ValueGroup < 0 {
		return fmt.Errorf("%s: invalid regex value group %d, must be non-negative", r.ID, r.ValueGroup)
	}
	if r.Regex == "" && r.ValueGroup != 0 {
		return fmt.Errorf("%s: regex value group %d requires a regex", r.ID, r.ValueGroup)
	}
	if r.Regex != "" && r.ValueGroup > maxCapture {
		return fmt.Errorf("%s: invalid regex value group %d, max regex value group %d", r.ID, r.ValueGroup, maxCapture)
	}
	if strings.TrimSpace(r.AnalyzeExpr) != "" && strings.TrimSpace(r.ValidateExpr) == "" {
		return fmt.Errorf("%s: analyze expression requires a validate expression", r.ID)
	}

	if r.Regex == "" && (len(r.Components) > 0 || strings.TrimSpace(r.ValidateExpr) != "" || strings.TrimSpace(r.AnalyzeExpr) != "" || strings.TrimSpace(r.RevokeExpr) != "") {
		return fmt.Errorf("%s: path-only rules cannot declare components, validation, analysis, or revocation", r.ID)
	}

	seenComponents := make(map[string]struct{}, len(r.Components))
	for _, component := range r.Components {
		if strings.TrimSpace(component.RuleID) == "" {
			return fmt.Errorf("%s: component rule ID is empty", r.ID)
		}
		if component.RuleID == r.ID {
			return fmt.Errorf("%s: rule cannot reference itself as a component", r.ID)
		}
		if _, exists := seenComponents[component.RuleID]; exists {
			return fmt.Errorf("%s: duplicate component rule ID %q", r.ID, component.RuleID)
		}
		seenComponents[component.RuleID] = struct{}{}
		if _, err := contextwindow.Parse(component.Within); err != nil {
			return fmt.Errorf("%s: component %q has invalid within value %q: %w", r.ID, component.RuleID, component.Within, err)
		}
	}

	return nil
}

// validatePatterns checks syntax without creating runtime regex objects.
// Translation also calls it before merging to reject invalid definitions even
// when a later duplicate or extension would replace their patterns.
func (r *Rule) validatePatterns() (int, error) {
	if r.Path != "" {
		if _, err := syntax.Parse(r.Path, syntax.Perl); err != nil {
			return 0, fmt.Errorf("%s: invalid path regex %q: %w", r.ID, r.Path, err)
		}
	}
	maxCapture := 0
	if r.Regex != "" {
		parsed, err := syntax.Parse(r.Regex, syntax.Perl)
		if err != nil {
			return 0, fmt.Errorf("%s: invalid regex %q: %w", r.ID, r.Regex, err)
		}
		maxCapture = parsed.MaxCap()
	}

	return maxCapture, nil
}
