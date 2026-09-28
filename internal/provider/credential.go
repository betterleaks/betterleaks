package provider

import (
	"errors"
	"fmt"
	"maps"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/expr-lang/expr/ast"
	exprparser "github.com/expr-lang/expr/parser"
)

// RequirementsFor finds required captures for the expressions that will execute.
func RequirementsFor(rule config.Rule, primaryCaptures map[string]string, expressions ...string) credential.Requirements {
	refs := captureReferences(expressions...)
	result := credential.Requirements{Captures: requiredNames(refs[""], primaryCaptures[rule.ID])}
	for _, component := range rule.Components {
		result.Components = append(result.Components, credential.ComponentRequirements{
			RuleID: component.RuleID, Optional: component.Optional,
			Captures: requiredNames(refs[component.RuleID], primaryCaptures[component.RuleID]),
		})
	}
	slices.SortFunc(result.Components, func(a, b credential.ComponentRequirements) int { return strings.Compare(a.RuleID, b.RuleID) })
	return result
}

// PrimaryCapture returns the name of the capture selected as the rule's value,
// or an empty string when it is unnamed or cannot be inferred without matching.
func PrimaryCapture(rule config.Rule) string {
	re, err := syntax.Parse(rule.Regex, syntax.Perl)
	if err != nil {
		return ""
	}
	group := rule.ValueGroup
	// With multiple default groups the scanner chooses the first nonempty one;
	// its name cannot be inferred from an extracted credential alone.
	if group == 0 && re.MaxCap() == 1 {
		group = 1
	}
	names := re.CapNames()
	if group > 0 && group < len(names) {
		return names[group]
	}
	return ""
}

func requiredNames(refs map[string]bool, primary string) []string {
	var names []string
	for name := range refs {
		if name != primary {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

type nodeVisitor func(*ast.Node)

func (v nodeVisitor) Visit(n *ast.Node) { v(n) }

func captureReferences(expressions ...string) map[string]map[string]bool {
	refs := make(map[string]map[string]bool)
	for _, expression := range expressions {
		tree, err := exprparser.Parse(expression)
		if err != nil {
			continue
		} // Program compilation reports syntax errors.
		optional := make(map[ast.Node]bool)
		ast.Walk(&tree.Node, nodeVisitor(func(n *ast.Node) {
			if binary, ok := (*n).(*ast.BinaryNode); ok && binary.Operator == "??" {
				ast.Walk(&binary.Left, nodeVisitor(func(child *ast.Node) { optional[*child] = true }))
			}
		}))
		ast.Walk(&tree.Node, nodeVisitor(func(n *ast.Node) {
			if optional[*n] {
				return
			}
			path, ok := capturePath(*n)
			if !ok {
				return
			}
			id, name := "", ""
			if len(path) == 3 && path[0] == "finding" && path[1] == "captures" {
				name = path[2]
			}
			if len(path) == 4 && path[0] == "components" && path[2] == "captures" {
				id, name = path[1], path[3]
			}
			if name == "" {
				return
			}
			if refs[id] == nil {
				refs[id] = make(map[string]bool)
			}
			refs[id][name] = true
		}))
	}
	return refs
}

func capturePath(node ast.Node) ([]string, bool) {
	switch n := node.(type) {
	case *ast.IdentifierNode:
		return []string{n.Value}, true
	case *ast.MemberNode:
		if n.Optional {
			return nil, false
		}
		key, ok := n.Property.(*ast.StringNode)
		if !ok {
			return nil, false
		}
		path, ok := capturePath(n.Node)
		return append(path, key.Value), ok
	case *ast.ChainNode:
		return capturePath(n.Node)
	}
	return nil, false
}

// ValidateFinding checks credential values and required captures, normalizing
// selected secret captures and component optionality in place. The caller must
// own the finding and its maps and slices; use Finding.Clone when needed.
func ValidateFinding(f *report.Finding, rule config.Rule, requirements credential.Requirements, rules map[string]config.Rule, primaryCaptures map[string]string) error {
	if err := validateMatch("secret", &f.Match, rule, requirements.Captures, primaryCaptures[rule.ID]); err != nil {
		return err
	}
	declared := make(map[string]credential.ComponentRequirements, len(requirements.Components))
	for _, c := range requirements.Components {
		declared[c.RuleID] = c
	}
	if len(f.ComponentSets) == 0 {
		for _, c := range requirements.Components {
			if !c.Optional {
				return fmt.Errorf("missing required component(s): %s", c.RuleID)
			}
		}
	}
	for index, set := range f.ComponentSets {
		seen := make(map[string]bool, len(set.Components))
		for i := range set.Components {
			c := &set.Components[i]
			requirement, ok := declared[c.RuleID]
			if !ok {
				return fmt.Errorf("component %q not declared by rule %q", c.RuleID, rule.ID)
			}
			if seen[c.RuleID] {
				return fmt.Errorf("component set %d repeats component %q", index, c.RuleID)
			}
			seen[c.RuleID] = true
			c.Optional = requirement.Optional
			if err := validateMatch(fmt.Sprintf("component %q", c.RuleID), &c.Match, rules[c.RuleID], requirement.Captures, primaryCaptures[c.RuleID]); err != nil {
				return err
			}
		}
		for _, c := range requirements.Components {
			if !c.Optional && !seen[c.RuleID] {
				return fmt.Errorf("component set %d missing required component(s): %s", index, c.RuleID)
			}
		}
	}
	return nil
}

func validateMatch(label string, match *report.Match, rule config.Rule, required []string, primaryName string) error {
	if err := validateSecret(label, match.Value); err != nil {
		return err
	}
	if err := validateCaptures(match.Captures); err != nil {
		return err
	}
	if name := primaryName; name != "" {
		if value, ok := match.Captures[name]; ok && value != match.Value {
			return fmt.Errorf("%s capture %q disagrees with its value", label, name)
		}
		if match.Captures == nil {
			match.Captures = make(map[string]string)
		}
		match.Captures[name] = match.Value
	}
	var missing []string
	for _, name := range required {
		if match.Captures[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required capture(s) for rule %q: %s", rule.ID, strings.Join(missing, ", "))
	}
	return nil
}

// FindingFromCredential returns an independent snapshot for provider execution using the
// selected rule. It copies all mutable data and does not invent scan locations
// or matched source text. The caller must resolve rule from Input.RuleID.
func FindingFromCredential(input credential.Input, rule config.Rule) report.Finding {
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
