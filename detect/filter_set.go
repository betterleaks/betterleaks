package detect

import (
	"fmt"
	"sync"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
)

// FilterSet compiles and caches global and per-rule filter programs.
type FilterSet struct {
	cfg     *config.Config
	runtime *exprruntime.Runtime

	mu      sync.Mutex
	global  exprruntime.Program
	perRule map[string]exprruntime.Program
}

// NewFilterSet creates a FilterCache backed by cfg and rt.
func NewFilterSet(cfg *config.Config, rt *exprruntime.Runtime) *FilterSet {
	return &FilterSet{
		cfg:     cfg,
		runtime: rt,
		perRule: make(map[string]exprruntime.Program),
	}
}

// Global compiles (once) and returns the config's global filter program.
func (fc *FilterSet) Global() (exprruntime.Program, bool, error) {
	if fc.cfg.Filter == "" {
		return nil, false, nil
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.global != nil {
		return fc.global, true, nil
	}
	prg, err := fc.runtime.CompileFilter(fc.cfg.Filter, nil)
	if err != nil {
		return nil, false, fmt.Errorf("compiling global filter: %w", err)
	}
	fc.global = prg
	return prg, true, nil
}

// ForRule compiles (once) and returns the filter program for the given rule.
func (fc *FilterSet) ForRule(r config.Rule) (exprruntime.Program, bool, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	rule := r
	cacheable := false
	if cfgRule, ok := fc.cfg.Rules[r.RuleID]; ok {
		rule = cfgRule
		cacheable = true
	}
	if rule.Filter == "" {
		return nil, false, nil
	}
	if cacheable {
		if prg := fc.perRule[rule.RuleID]; prg != nil {
			return prg, true, nil
		}
	}
	if prg := rule.FilterProgram(); prg != nil {
		return prg, true, nil
	}
	prg, err := fc.runtime.CompileFilter(rule.Filter, nil)
	if err != nil {
		return nil, false, fmt.Errorf("compiling rule %s filter: %w", rule.RuleID, err)
	}
	if cacheable {
		fc.perRule[rule.RuleID] = prg
	}
	return prg, true, nil
}
