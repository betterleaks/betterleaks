package analyze

import (
	"fmt"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/limits"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/expr-lang/expr/ast"
	exprparser "github.com/expr-lang/expr/parser"
)

// CredentialRequirements describes the statically named inputs consumed by a
// rule's provider expressions. Optional accesses and null-coalescing fallbacks
// do not require a capture. Dynamic capture names cannot be inferred.
type CredentialRequirements struct {
	Captures   []string                `json:"captures,omitempty"`
	Components []ComponentRequirements `json:"components,omitempty"`
}

// ComponentRequirements describes one declared credential component. Captures
// are required only when that component is supplied.
type ComponentRequirements struct {
	RuleID   string   `json:"rule_id"`
	Optional bool     `json:"optional,omitempty"`
	Captures []string `json:"captures,omitempty"`
}

// Requirements returns the inputs needed for validation and analysis. The
// returned slices are independent of the Analyzer's configuration.
func (a *Analyzer) Requirements(ruleID string) (CredentialRequirements, error) {
	return a.ruleRequirements(ruleID, true)
}

// ValidationRequirements returns only the inputs needed to check liveness.
func (a *Analyzer) ValidationRequirements(ruleID string) (CredentialRequirements, error) {
	return a.ruleRequirements(ruleID, false)
}

func (a *Analyzer) ruleRequirements(ruleID string, analysis bool) (CredentialRequirements, error) {
	if a == nil || a.runtime == nil {
		return CredentialRequirements{}, fmt.Errorf("analyzer must be constructed with New")
	}
	rule, ok := a.rules[ruleID]
	if !ok {
		return CredentialRequirements{}, fmt.Errorf("rule %q not found in config", ruleID)
	}
	return a.requirementsFor(rule, analysis), nil
}

func (a *Analyzer) requirementsFor(rule config.Rule, analysis bool) CredentialRequirements {
	expressions := []string{rule.ValidateExpr}
	if analysis {
		expressions = append(expressions, rule.AnalyzeExpr)
	}
	refs := captureReferences(expressions...)
	result := CredentialRequirements{Captures: requiredNames(refs[""], a.primaryCaptures[rule.ID])}
	for _, component := range rule.Components {
		result.Components = append(result.Components, ComponentRequirements{
			RuleID: component.RuleID, Optional: component.Optional,
			Captures: requiredNames(refs[component.RuleID], a.primaryCaptures[component.RuleID]),
		})
	}
	slices.SortFunc(result.Components, func(a, b ComponentRequirements) int { return strings.Compare(a.RuleID, b.RuleID) })
	return result
}

func primaryCapture(rule config.Rule) string {
	re, err := syntax.Parse(rule.Regex, syntax.Perl)
	if err != nil {
		return ""
	}
	group := rule.SecretGroup
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

// validateFindingInput runs only on the Analyzer's owned snapshot. It normalizes
// selected secret captures and component optionality without touching the caller.
func (a *Analyzer) validateFindingInput(f *report.Finding, rule config.Rule, requirements CredentialRequirements) error {
	if err := validateMatchInput("secret", &f.Match, rule, requirements.Captures, a.primaryCaptures[rule.ID]); err != nil {
		return err
	}
	declared := make(map[string]ComponentRequirements, len(requirements.Components))
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
			if err := validateMatchInput(fmt.Sprintf("component %q", c.RuleID), &c.Match, a.rules[c.RuleID], requirement.Captures, a.primaryCaptures[c.RuleID]); err != nil {
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

func validateMatchInput(label string, match *report.Match, rule config.Rule, required []string, primaryName string) error {
	if err := validateCredentialSecret(label, match.Value); err != nil {
		return err
	}
	if err := validateCredentialCaptures(match.Captures); err != nil {
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

// Keep the Analyzer's public handoff bounded as well as Scanner discovery.
const maxComponentSets = limits.ComponentSets
