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
	ID string `toml:"id"`

	// Description is the description of the rule.
	Description string `toml:"description"`

	// ValueGroup selects the capture group used for Match.Value.
	// Positive values are 1-based capture group indexes.
	// Zero selects the first non-empty capture group, falling back to
	// Match.Full if none exists. An explicitly selected group that
	// does not participate produces an empty value.
	ValueGroup int `toml:"valueGroup"`

	// Regex is a Go regular expression pattern used to detect secrets.
	// An empty pattern disables content matching. Scanner owns compilation.
	Regex string `toml:"regex"`

	// Path is a Go regular expression pattern used to filter secrets by path.
	// An empty pattern matches any path when Regex is set.
	Path string `toml:"path"`

	// Tags is an array of strings used for metadata
	// and reporting purposes.
	Tags []string `toml:"tags"`

	// Specificity controls precedence when overlapping findings compete.
	// Higher specificity findings suppress lower specificity findings.
	// Zero is the default; negative values lower precedence and positive values raise it.
	Specificity int `toml:"specificity"`

	// Confidence estimates how likely a match is to be a real secret.
	Confidence string `toml:"confidence"`

	// Keywords are used for pre-regex check filtering. Rules that contain
	// keywords will perform a quick string compare check to make sure the
	// keyword(s) are in the content being scanned.
	Keywords []string `toml:"keywords"`

	// Components are other rules whose matches contribute to this rule.
	// Required components gate the rule; optional components are attached when found.
	Components []Component `toml:"components"`

	SkipReport bool `toml:"skipReport"`

	// ValidateExpr is the raw expression used for secret validation.
	ValidateExpr string `toml:"validate"`

	// AnalyzeExpr is the raw expression used to enrich a valid credential with
	// identity and provider-neutral capabilities.
	AnalyzeExpr string `toml:"analyze"`

	// RevokeExpr is an optional credential revocation program. It executes only
	// through the explicit revoke command, never during scanning or analysis.
	RevokeExpr string `toml:"revoke"`

	// FilterExpr is an expression evaluated against attributes + finding per regex match.
	// finding.captures holds this match's named groups. Components are assembled
	// after filtering. Provider expressions, including explicit revocation, read
	// supplied components independently of filtering.
	// Returns true = skip (discard this finding); false = keep.
	FilterExpr string `toml:"filter"`

	// Tests are detection fixtures executed by config check, never by scanning.
	Tests []RuleTest `toml:"tests,omitempty"`
}

// RuleTest describes one source fragment and its exact expected findings for the
// owning rule. Other rules run only when referenced as components.
type RuleTest struct {
	Name       string            `toml:"name"`
	Mode       string            `toml:"mode,omitempty"`
	Input      string            `toml:"input"`
	Attributes map[string]string `toml:"attributes,omitempty"`
	// Expect must be explicit. An empty array asserts no findings.
	Expect []ExpectedFinding `toml:"expect"`
}

// ExpectedFinding asserts the extracted value, named captures, and component
// combinations. Ordering is ignored, but duplicate findings are counted.
type ExpectedFinding struct {
	// Rule may be omitted; when supplied it must identify the owning rule.
	Rule          string              `toml:"rule,omitempty"`
	Secret        string              `toml:"secret"`
	Captures      map[string]string   `toml:"captures,omitempty"`
	ComponentSets []map[string]string `toml:"componentSets,omitempty"`
}

// Component references another rule that contributes a nearby match to a multipart finding.
type Component struct {
	RuleID string `toml:"id"`
	// Optional components are attached when found but do not gate the primary finding.
	Optional bool `toml:"optional"`
	// Within uses the same directional L/C grammar as --match-context.
	Within string `toml:"within"`
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

	return r.validateTests()
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

func (r *Rule) validateTests() error {
	names := make(map[string]bool, len(r.Tests))
	for i, test := range r.Tests {
		fail := func(message string) error {
			return fmt.Errorf("rule %q test %d (%q): %s", r.ID, i+1, test.Name, message)
		}
		if strings.TrimSpace(test.Name) == "" || names[test.Name] {
			return fail("test names must be nonempty and unique within a rule")
		}
		names[test.Name] = true
		if test.Expect == nil {
			return fail("expect is required; use [] for a negative case")
		}
		switch test.Mode {
		case "", "finding":
		case "match":
			if !r.SkipReport || len(r.Components) != 0 {
				return fail("match mode requires an owning skipReport leaf rule")
			}
		default:
			return fail(fmt.Sprintf("unknown mode %q", test.Mode))
		}
		for _, expected := range test.Expect {
			if expected.Rule != "" && expected.Rule != r.ID {
				return fail(fmt.Sprintf("expected rule must be %q", r.ID))
			}
			for _, set := range expected.ComponentSets {
				for id := range set {
					found := false
					for _, component := range r.Components {
						found = found || component.RuleID == id
					}
					if !found {
						return fail(fmt.Sprintf("unknown expected component %q", id))
					}
				}
			}
		}
	}
	return nil
}
