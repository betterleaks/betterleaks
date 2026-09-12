package provider

import (
	"regexp/syntax"
	"sort"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/expr-lang/expr/ast"
	exprparser "github.com/expr-lang/expr/parser"
)

// RequiredCaptures lists named regex captures referenced by the supplied
// expressions, excluding the primary secret group. With no expressions it
// examines the rule's validation expression.
func RequiredCaptures(rule configpkg.Rule, expressions ...string) []string {
	if rule.Regex == "" {
		return nil
	}
	if len(expressions) == 0 {
		expressions = []string{rule.ValidateExpr}
	}
	referenced := make(map[string]struct{})
	for _, expression := range expressions {
		for name := range referencedValidationCaptures(expression) {
			referenced[name] = struct{}{}
		}
	}
	parsed, err := syntax.Parse(rule.Regex, syntax.Perl)
	if err != nil {
		return nil
	}
	names := parsed.CapNames()
	required := make([]string, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for index, name := range names {
		if name == "" || index == rule.SecretGroup {
			continue
		}
		if _, ok := referenced[name]; !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		required = append(required, name)
	}
	sort.Strings(required)
	return required
}

type validationCaptureCollector map[string]struct{}

func (c validationCaptureCollector) Visit(node *ast.Node) {
	member, ok := (*node).(*ast.MemberNode)
	if !ok || !isValidationCaptureObject(member.Node) {
		return
	}
	property, ok := member.Property.(*ast.StringNode)
	if ok && property.Value != "" {
		c[property.Value] = struct{}{}
	}
}

func referencedValidationCaptures(expression string) map[string]struct{} {
	captures := validationCaptureCollector{}
	tree, err := exprparser.Parse(expression)
	if err != nil {
		return captures
	}
	ast.Walk(&tree.Node, captures)
	return captures
}

func isValidationCaptureObject(node ast.Node) bool {
	for {
		chain, ok := node.(*ast.ChainNode)
		if !ok {
			break
		}
		node = chain.Node
	}
	member, ok := node.(*ast.MemberNode)
	if !ok {
		return false
	}
	property, ok := member.Property.(*ast.StringNode)
	if !ok || property.Value != "captures" {
		return false
	}
	base, ok := member.Node.(*ast.IdentifierNode)
	return ok && base.Value == "finding"
}
