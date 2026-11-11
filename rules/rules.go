// Package rules defines Betterleaks' default rules. Each provider file
// registers its rules with Add, and go generate renders every registered rule
// into config/betterleaks.toml.
//
// No API stability is guaranteed for this package.
package rules

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
)

//go:generate go run ./gen ../config/betterleaks.toml

type registration struct {
	rule config.Rule
	file string
}

var registered []registration

// Add registers rules for the default config. Call it from a package-level
// declaration in the provider's file:
//
//	var _ = Add(config.Rule{...})
func Add(rules ...config.Rule) struct{} {
	_, file, _, _ := runtime.Caller(1)
	file = "rules/" + filepath.Base(file)
	for _, rule := range rules {
		rule.Keywords = normalizeKeywords(rule.Keywords)
		registered = append(registered, registration{rule: rule, file: file})
	}
	return struct{}{}
}

// Config returns the default config: global policy plus every registered
// rule, sorted by ID.
func Config() (*config.Config, error) {
	cfg := baseConfig()
	files := make(map[string]string, len(registered))
	for _, r := range registered {
		if previous, ok := files[r.rule.ID]; ok {
			return nil, fmt.Errorf("%s: rule %q is already defined in %s", r.file, r.rule.ID, previous)
		}
		if err := r.rule.Validate(); err != nil {
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

// baseConfig holds the global policy without any rules.
func baseConfig() *config.Config {
	return &config.Config{
		Title:         "betterleaks config",
		PrefilterExpr: GlobalPrefilter,
		FilterExpr:    GlobalFilter,
	}
}

// sourceFile reports the file that registered a rule, for test failures.
func sourceFile(id string) string {
	for _, r := range registered {
		if r.rule.ID == id {
			return r.file
		}
	}
	return "rules"
}

// Keywords match case-insensitively, so store each one once in lowercase.
func normalizeKeywords(keywords []string) []string {
	if keywords == nil {
		return nil
	}
	normalized := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		keyword = strings.ToLower(keyword)
		if !slices.Contains(normalized, keyword) {
			normalized = append(normalized, keyword)
		}
	}
	return normalized
}

// Token matches a credential with a distinctive format, such as a fixed
// prefix, bounded by the standard token delimiters. A leading (?i) makes the
// whole pattern case-insensitive.
func Token(pattern string) string {
	pattern, insensitive := strings.CutPrefix(pattern, "(?i)")
	return uniqueTokenRegex(pattern, insensitive)
}

// Assignment matches a credential assigned to a name containing one of names,
// such as ACME_SECRET = "...". Names are case-insensitive regex fragments. A
// leading (?i) makes the value pattern case-insensitive too.
func Assignment(names []string, pattern string) string {
	pattern, insensitive := strings.CutPrefix(pattern, "(?i)")
	return semiGenericRegex(names, pattern, insensitive)
}

// Match is a test whose input must produce exactly one finding, secret.
func Match(name, input, secret string) config.RuleTest {
	return config.RuleTest{Name: name, Input: input, Expect: []config.ExpectedFinding{{Secret: secret}}}
}

// NoMatch is a test whose input must produce no findings.
func NoMatch(name, input string) config.RuleTest {
	return config.RuleTest{Name: name, Input: input, Expect: []config.ExpectedFinding{}}
}
