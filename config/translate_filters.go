package config

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
)

// normalizeRuleFilters folds the entropy and token-efficiency shorthands into
// each rule's Expr filter.
func (c *Config) normalizeRuleFilters() {
	for ruleID, r := range c.Rules {
		var filters []string

		if r.Entropy != 0 {
			threshold := fmt.Sprintf("%g", r.Entropy)
			if !strings.ContainsAny(threshold, ".e") {
				threshold += ".0"
			}
			filters = append(filters, fmt.Sprintf(`entropy(finding["secret"]) <= %s`, threshold))
		}
		if r.TokenEfficiency {
			filters = append(filters, `failsTokenEfficiency(finding["secret"])`)
		}

		r.Filter = composeFilters(filters, r.Filter)

		if r.Filter != "" {
			logging.Trace().Str("rule", ruleID).Str("filter", r.Filter).
				Msg("translated rule filter expression")
		}

		r.Entropy = 0
		r.TokenEfficiency = false
		c.Rules[ruleID] = r
	}
}

// composeFilters builds a final Expr expression from skip predicates.
// Each part is a condition that, when true, means "skip this item".
// Parts are OR-ed: skip if any condition fires.
// If all inputs are empty, returns "".
func composeFilters(skipParts []string, userExpr string) string {
	var parts []string
	for _, sp := range skipParts {
		parts = append(parts, sp)
	}
	if userExpr != "" {
		if len(parts) > 0 && startsWithLet(userExpr) {
			userExpr = "(" + userExpr + ")"
		}
		parts = append(parts, userExpr)
	}
	if len(parts) <= 1 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts, "\n|| ")
}

func startsWithLet(expr string) bool {
	for expr = strings.TrimSpace(expr); strings.HasPrefix(expr, "//"); expr = strings.TrimSpace(expr) {
		newline := strings.IndexByte(expr, '\n')
		if newline < 0 {
			return false
		}
		expr = expr[newline+1:]
	}
	return strings.HasPrefix(expr, "let ")
}
