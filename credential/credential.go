// Package credential owns inputs, capture requirements, and input preparation
// shared by validation, analysis, and explicit revocation.
package credential

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
)

// Input is an already-extracted secret and the inputs needed by its rule's
// provider programs. Secret is passed verbatim: it is not matched against the
// detection regex, decoded, or trimmed. Additional captures are supplied explicitly.
// Primary and component secrets must each contain between 1 byte and 1 MiB.
// Provider expressions read Secret as finding.secret and Captures as
// finding.captures. Components are exposed as components[ruleID], with the
// same secret and captures fields for each component.
type Input struct {
	RuleID   string
	Secret   string
	Captures map[string]string
	// Components contains one credential combination, keyed by component rule ID.
	Components map[string]Component
	// Attributes are report metadata only; provider expressions cannot read them.
	Attributes map[string]string
}

// Component supplies a component value and its named captures.
type Component struct {
	Secret   string
	Captures map[string]string
}

// Finding returns an independent snapshot for provider execution using the
// selected rule. It copies all mutable data and does not invent scan locations
// or matched source text. The caller must resolve rule from Input.RuleID.
func (input Input) Finding(rule config.Rule) report.Finding {
	optional := make(map[string]bool, len(rule.Components))
	for _, c := range rule.Components {
		optional[c.RuleID] = c.Optional
	}

	finding := report.Finding{
		RuleID:      rule.ID,
		Description: rule.Description,
		Match:       report.Match{Value: input.Secret, Captures: maps.Clone(input.Captures)},
		Tags:        slices.Clone(rule.Tags),
	}
	finding.SetAttributes(input.Attributes)
	components := make([]report.ComponentFinding, 0, len(input.Components))
	for _, id := range slices.Sorted(maps.Keys(input.Components)) {
		component := input.Components[id]
		components = append(components, report.ComponentFinding{
			RuleID:   id,
			Optional: optional[id],
			Match:    report.Match{Value: component.Secret, Captures: maps.Clone(component.Captures)},
		})
	}
	if len(components) > 0 {
		finding.ComponentSets = []report.ComponentSet{{Components: components}}
	}
	return finding
}

func validateSecret(label, secret string) error {
	if secret == "" {
		return fmt.Errorf("%s must not be empty", label)
	}
	const maxSecretBytes = 1 << 20
	if len(secret) > maxSecretBytes {
		return fmt.Errorf("%s exceeds %d bytes", label, maxSecretBytes)
	}
	return nil
}

func validateCaptures(captures map[string]string) error {
	for name := range captures {
		if name == "" {
			return errors.New("capture name must not be empty")
		}
	}
	return nil
}
