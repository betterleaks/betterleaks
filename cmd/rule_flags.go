package cmd

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
)

// expandRuleFlagShorthands translates the multi-character aliases requested by
// the CLI into long flags. Kong reserves short flags for one-character names.
func expandRuleFlagShorthands(args []string) []string {
	expanded := make([]string, len(args))
	flagsEnded := false
	for i, arg := range args {
		if flagsEnded {
			expanded[i] = arg
			continue
		}
		if arg == "--" {
			flagsEnded = true
			expanded[i] = arg
			continue
		}
		switch {
		case arg == "-dr":
			expanded[i] = "--disable-rule"
		case strings.HasPrefix(arg, "-dr="):
			expanded[i] = "--disable-rule=" + strings.TrimPrefix(arg, "-dr=")
		case arg == "-ir":
			expanded[i] = "--isolate-rule"
		case strings.HasPrefix(arg, "-ir="):
			expanded[i] = "--isolate-rule=" + strings.TrimPrefix(arg, "-ir=")
		default:
			expanded[i] = arg
		}
	}
	return expanded
}

func applyRuleSelection(flags *ScanFlags, cfg *config.Config) error {
	isolateRules := flags.IsolateRule
	disableRules := flags.DisableRule
	if len(isolateRules) == 0 && len(disableRules) == 0 {
		return nil
	}

	availableRules := make(map[string]config.Rule, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		availableRules[rule.RuleID] = rule
	}
	disabledRuleIDs := make(map[string]struct{}, len(disableRules))
	for _, ruleID := range disableRules {
		if _, ok := availableRules[ruleID]; !ok {
			return fmt.Errorf("requested rule %q not found in rules", ruleID)
		}
		disabledRuleIDs[ruleID] = struct{}{}
	}

	selectedRules := make(map[string]config.Rule, len(availableRules))
	if len(isolateRules) > 0 {
		logging.Info().Msg("Isolating rules: " + strings.Join(isolateRules, ", "))
		for _, ruleID := range isolateRules {
			rule, ok := availableRules[ruleID]
			if !ok {
				return fmt.Errorf("requested rule %q not found in rules", ruleID)
			}
			if _, disabled := disabledRuleIDs[ruleID]; disabled {
				continue
			}
			selectedRules[ruleID] = rule
		}

		// Component rules are implementation details of an isolated rule. Keep
		// them available for component matching while suppressing top-level
		// reports unless the user explicitly isolated the component too.
		queue := make([]config.Rule, 0, len(selectedRules))
		for _, rule := range selectedRules {
			queue = append(queue, rule)
		}
		for len(queue) > 0 {
			rule := queue[0]
			queue = queue[1:]
			for _, component := range rule.Components {
				if _, disabled := disabledRuleIDs[component.RuleID]; disabled {
					continue
				}
				if _, selected := selectedRules[component.RuleID]; selected {
					continue
				}
				componentRule, ok := availableRules[component.RuleID]
				if !ok {
					return fmt.Errorf("component rule %q referenced by %q not found in rules", component.RuleID, rule.RuleID)
				}
				componentRule.SkipReport = true
				selectedRules[component.RuleID] = componentRule
				queue = append(queue, componentRule)
			}
		}
	} else {
		for ruleID, rule := range availableRules {
			if _, disabled := disabledRuleIDs[ruleID]; disabled {
				continue
			}
			selectedRules[ruleID] = rule
		}
	}

	if len(disableRules) > 0 {
		logging.Info().Msg("Disabling rules: " + strings.Join(disableRules, ", "))
	}

	selected := make([]config.Rule, 0, len(selectedRules))
	for _, rule := range cfg.Rules {
		if selectedRule, ok := selectedRules[rule.RuleID]; ok {
			selected = append(selected, selectedRule)
		}
	}
	cfg.Rules = selected
	return nil
}
