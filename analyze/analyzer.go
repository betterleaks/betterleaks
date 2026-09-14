// Package analyze resolves credential liveness, identity, and permissions using
// provider Expr programs. It does not discover secrets or read source content.
package analyze

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
)

type programs struct {
	validation exprruntime.Program
	analysis   exprruntime.Program
}

// Analyzer owns an immutable rule snapshot and compiled provider programs.
// Calls may run concurrently. Each operation gets fresh provider workers,
// result caches, and request limits; compiled programs are shared across calls.
// Construction starts no workers and sends no requests.
type Analyzer struct {
	rules         map[string]config.Rule
	options       options
	runtime       *exprruntime.Runtime
	mu            sync.Mutex
	programs      map[string]programs
	hasValidation bool
	hasAnalysis   bool
}

// New snapshots cfg and validates runtime options. Programs compile lazily
// unless WithPrecompile is supplied. Scan filters are never compiled here.
func New(cfg *config.Config, opts ...Option) (*Analyzer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	settings := options{workers: 10, logger: slog.New(slog.DiscardHandler)}
	for _, option := range opts {
		if option.apply == nil {
			return nil, errors.New("analyzer option is invalid")
		}
		if err := option.apply(&settings); err != nil {
			return nil, err
		}
	}
	settings.RequestsPerSecondByRule = maps.Clone(settings.RequestsPerSecondByRule)
	settings.EnvVars = slices.Clone(settings.EnvVars)
	runtime, err := provider.NewRuntime(settings.RuntimeOptions)
	if err != nil {
		return nil, err
	}
	a := &Analyzer{rules: make(map[string]config.Rule, len(cfg.Rules)), options: settings, runtime: runtime, programs: make(map[string]programs)}
	for _, source := range cfg.Rules {
		rule := source
		rule.Tags = slices.Clone(source.Tags)
		rule.Keywords = slices.Clone(source.Keywords)
		rule.Components = make([]*config.Component, len(source.Components))
		for i, component := range source.Components {
			copy := *component
			rule.Components[i] = &copy
		}
		a.rules[rule.ID] = rule
		a.hasValidation = a.hasValidation || rule.ValidateExpr != ""
		a.hasAnalysis = a.hasAnalysis || (rule.ValidateExpr != "" && rule.AnalyzeExpr != "")
		if settings.precompile {
			if _, err := a.programsFor(rule, true); err != nil {
				return nil, err
			}
		}
	}
	return a, nil
}

// HasValidation reports whether the configuration contains validation programs.
func (a *Analyzer) HasValidation() bool { return a != nil && a.hasValidation }

// HasAnalysis reports whether a rule can analyze a validated credential.
func (a *Analyzer) HasAnalysis() bool { return a != nil && a.hasAnalysis }

func (a *Analyzer) programsFor(rule config.Rule, analysis bool) (programs, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.programs[rule.ID]
	var err error
	if p.validation == nil && rule.ValidateExpr != "" {
		p.validation, err = a.runtime.CompileValidation(rule.ValidateExpr)
		if err != nil {
			return p, fmt.Errorf("compiling rule %s validation: %w", rule.ID, err)
		}
	}
	if analysis && p.analysis == nil && rule.AnalyzeExpr != "" {
		p.analysis, err = a.runtime.CompileAnalysis(rule.AnalyzeExpr)
		if err != nil {
			return p, fmt.Errorf("compiling rule %s analysis: %w", rule.ID, err)
		}
	}
	a.programs[rule.ID] = p
	if !analysis {
		p.analysis = nil
	}
	return p, nil
}

// Validate determines a finding's credential state without running analysis.
// The input is not mutated. Rules without validation return an unresolved
// finding. Unknown rules and compilation failures return Go errors; provider
// failures are represented by Validation.Status.
func (a *Analyzer) Validate(ctx context.Context, finding report.Finding) (report.Finding, error) {
	return a.resolve(ctx, finding, false)
}

// Analyze validates a finding and resolves identity and permissions when valid.
// A finding carries all required captures, components, and expression context;
// the analyzer never needs to read the original source.
func (a *Analyzer) Analyze(ctx context.Context, finding report.Finding) (report.Finding, error) {
	return a.resolve(ctx, finding, true)
}

func (a *Analyzer) resolve(ctx context.Context, finding report.Finding, analysis bool) (report.Finding, error) {
	var result report.Finding
	err := a.stream(ctx, func(_ context.Context, yield func(report.Finding) error) error {
		return yield(finding)
	}, func(f report.Finding) error { result = f; return nil }, analysis, 1)
	return result, err
}
