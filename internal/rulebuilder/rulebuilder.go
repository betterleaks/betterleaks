// Package rulebuilder is the toolkit for writing Betterleaks' default rules in
// rules/: a registry, regex wrappers, shared expressions, and test constructors.
// Each provider file registers its rules with Add, and go generate renders
// them into config/betterleaks.toml.
package rulebuilder

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
)

type registration struct {
	rule config.Rule
	file string
}

var registered []registration

// Add registers rules for the default config. Call it from a package-level
// declaration in the provider's file:
//
//	var _ = rulebuilder.Add(config.Rule{...})
func Add(rules ...config.Rule) struct{} {
	_, file, _, _ := runtime.Caller(1)
	if i := strings.LastIndex(file, "/rules/"); i >= 0 {
		file = file[i+1:] // rules/acme.go or rules/generic/password.go
	}
	for _, rule := range rules {
		registered = append(registered, registration{rule: rule, file: file})
	}
	return struct{}{}
}

// Config returns the default config: global policy plus every registered
// rule, sorted by ID. The rules package must be imported for its rules to be
// registered.
func Config() (*config.Config, error) {
	if len(registered) == 0 {
		return nil, errors.New("no rules registered: import github.com/betterleaks/betterleaks/v2/rules")
	}
	cfg := baseConfig()
	files := make(map[string]string, len(registered))
	for _, r := range registered {
		if previous, ok := files[r.rule.ID]; ok {
			return nil, fmt.Errorf("%s: rule %q is already defined in %s", r.file, r.rule.ID, previous)
		}
		if err := r.rule.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", r.file, err)
		}
		if err := checkRule(r.rule); err != nil {
			return nil, fmt.Errorf("%s: %w", r.file, err)
		}
		files[r.rule.ID] = r.file
		cfg.Rules = append(cfg.Rules, r.rule)
	}
	slices.SortFunc(cfg.Rules, func(a, b config.Rule) int { return strings.Compare(a.ID, b.ID) })
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// File reports the file that registered rule id, for test failures.
func File(id string) string {
	for _, r := range registered {
		if r.rule.ID == id {
			return r.file
		}
	}
	return "rules"
}

// baseConfig holds the global policy without any rules.
func baseConfig() *config.Config {
	return &config.Config{
		Title:         "betterleaks config",
		PrefilterExpr: globalPrefilter,
		FilterExpr:    globalFilter,
	}
}

// checkRule enforces authoring conventions that config validation does not.
// A description still starting with TODO is an unfinished `make newrule`
// scaffold. Keywords match case-insensitively, so each must be written once,
// in lowercase, for the source to read the same as the generated config.
func checkRule(rule config.Rule) error {
	if strings.HasPrefix(strings.TrimSpace(rule.Description), "TODO") {
		return fmt.Errorf("rule %q: description still starts with TODO; replace the make newrule placeholders", rule.ID)
	}
	for i, keyword := range rule.Keywords {
		if keyword != strings.ToLower(keyword) {
			return fmt.Errorf("rule %q: keyword %q must be lowercase", rule.ID, keyword)
		}
		if slices.Contains(rule.Keywords[:i], keyword) {
			return fmt.Errorf("rule %q: duplicate keyword %q", rule.ID, keyword)
		}
	}
	return nil
}
