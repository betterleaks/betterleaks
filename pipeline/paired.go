package pipeline

import (
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// pairCoordinator keeps a generic finding until every provider rule that matched
// the same secret has finished validation. A live provider replaces the generic.
type pairCoordinator struct {
	seen []observedProvider
	held []*heldGeneric
}

type observedProvider struct {
	ruleID string
	status report.ValidationStatus
	value  string
	sha    string
	loc    report.Location
}

type heldGeneric struct {
	finding  report.Finding
	rules    []string
	resolved map[string]report.ValidationStatus
}

func (c *pairCoordinator) accept(f report.Finding) []report.Finding {
	rules := pairedRuleIDs(f)
	if isGenericRule(f.RuleID) {
		if len(rules) == 0 {
			return []report.Finding{f}
		}
		held := &heldGeneric{finding: f, rules: rules, resolved: make(map[string]report.ValidationStatus, len(rules))}
		for _, observed := range c.seen {
			noteProvider(held, observed)
		}
		if held.passed() {
			return nil
		}
		if !held.pending() {
			return []report.Finding{f}
		}
		c.held = append(c.held, held)
		return nil
	}

	observed := observedProvider{
		ruleID: f.RuleID,
		status: f.Analysis.Status,
		value:  f.Match.Value,
		sha:    f.Attributes[sources.AttrGitSHA],
		loc:    f.Location,
	}
	c.seen = append(c.seen, observed)
	ready := []report.Finding{f}
	remaining := make([]*heldGeneric, 0, len(c.held))
	for _, held := range c.held {
		noteProvider(held, observed)
		if held.passed() {
			continue
		}
		if !held.pending() {
			ready = append(ready, held.finding)
			continue
		}
		remaining = append(remaining, held)
	}
	c.held = remaining
	return ready
}

func (c *pairCoordinator) flush() []report.Finding {
	ready := make([]report.Finding, 0, len(c.held))
	for _, held := range c.held {
		if !held.passed() {
			ready = append(ready, held.finding)
		}
	}
	c.held = nil
	return ready
}

func noteProvider(held *heldGeneric, observed observedProvider) {
	if observed.value != held.finding.Match.Value || observed.sha != held.finding.Attributes[sources.AttrGitSHA] {
		return
	}
	if !locationsOverlap(held.finding.Location, observed.loc) {
		return
	}
	for _, ruleID := range held.rules {
		if ruleID != observed.ruleID {
			continue
		}
		if held.resolved[ruleID] == report.ValidationStatusValid {
			return
		}
		held.resolved[ruleID] = observed.status
		return
	}
}

func (h *heldGeneric) passed() bool {
	for _, status := range h.resolved {
		if status == report.ValidationStatusValid {
			return true
		}
	}
	return false
}

func (h *heldGeneric) pending() bool {
	for _, ruleID := range h.rules {
		if _, ok := h.resolved[ruleID]; !ok {
			return true
		}
	}
	return false
}

func pairedRuleIDs(f report.Finding) []string {
	raw := f.Attributes[sources.AttrScanPairedRules]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func isGenericRule(id string) bool {
	return strings.HasPrefix(id, "generic-")
}

func locationsOverlap(a, b report.Location) bool {
	return a.Path == b.Path && a.StartLine > 0 && b.StartLine > 0 &&
		(a.StartLine < b.EndLine || a.StartLine == b.EndLine && a.StartColumn <= b.EndColumn) &&
		(b.StartLine < a.EndLine || b.StartLine == a.EndLine && b.StartColumn <= a.EndColumn)
}
