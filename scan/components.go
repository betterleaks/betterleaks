package scan

import (
	"github.com/betterleaks/betterleaks/v2/internal/limits"
	"github.com/betterleaks/betterleaks/v2/report"
)

// buildComponentSets assembles complete credential combinations in discovery order.
// The hard cap bounds memory; truncated reports whether combinations were omitted.
func buildComponentSets(componentFindings []report.ComponentFinding, maxComponentSets int) ([]report.ComponentSet, bool) {
	maxComponentSets = min(maxComponentSets, limits.ComponentSets)
	truncated := false
	if len(componentFindings) == 0 {
		return nil, false
	}

	// Group by RuleID, preserving first-occurrence order.
	var ruleOrder []string
	byRule := make(map[string][]report.ComponentFinding)
	for _, rf := range componentFindings {
		if _, exists := byRule[rf.RuleID]; !exists {
			ruleOrder = append(ruleOrder, rf.RuleID)
		}
		byRule[rf.RuleID] = append(byRule[rf.RuleID], rf)
	}

	// Count only up to the limit, without overflowing or enumerating extra sets.
	total := 1
	for _, id := range ruleOrder {
		if maxComponentSets <= 0 || total > maxComponentSets/len(byRule[id]) {
			truncated = true
			break
		}
		total *= len(byRule[id])
	}
	if maxComponentSets <= 0 {
		return nil, true
	}
	products := cartesianFindings(ruleOrder, byRule, maxComponentSets)
	sets := make([]report.ComponentSet, len(products))
	for i, components := range products {
		sets[i] = report.ComponentSet{Components: components}
	}
	return sets, truncated
}

// cartesianFindings computes the Cartesian product over report.ComponentFinding slices
// keyed by ruleOrder. It stops early once maxComponentSets is reached.
func cartesianFindings(ruleOrder []string, byRule map[string][]report.ComponentFinding, maxComponentSets int) [][]report.ComponentFinding {
	if maxComponentSets <= 0 {
		return nil
	}
	for _, id := range ruleOrder {
		if len(byRule[id]) == 0 {
			return nil
		}
	}
	// Mixed-radix enumeration retains only the bounded output and one index per
	// component. Recursive intermediate products can otherwise dwarf the cap.
	indexes := make([]int, len(ruleOrder))
	var result [][]report.ComponentFinding
	for len(result) < maxComponentSets {
		row := make([]report.ComponentFinding, len(ruleOrder))
		for i, id := range ruleOrder {
			row[i] = byRule[id][indexes[i]]
		}
		result = append(result, row)
		position := len(indexes) - 1
		for ; position >= 0; position-- {
			indexes[position]++
			if indexes[position] < len(byRule[ruleOrder[position]]) {
				break
			}
			indexes[position] = 0
		}
		if position < 0 {
			break
		}
	}
	return result
}
