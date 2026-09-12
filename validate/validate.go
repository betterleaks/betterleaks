// Package validate checks already-extracted credentials using Betterleaks
// provider rules, without constructing a detector or scanning source content.
// Use config.Default or config.LoadFile to obtain rules, then NewValidator.
package validate

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
)

// Options controls direct credential validation. The zero value enables
// validation alone, using the provider runtime's default request timeout.
type Options struct {
	// Analysis also analyzes valid credentials when their rule defines analysis.
	Analysis bool
	// Debug includes sanitized provider HTTP metadata in reports.
	Debug bool
	// Timeout is the per-request timeout. Zero uses the runtime default.
	Timeout time.Duration
	// MaxRequestsPerTarget limits requests per provider origin per call. Zero is unlimited.
	MaxRequestsPerTarget int
	// RequestsPerSecond limits the provider request rate. Zero is unlimited.
	RequestsPerSecond float64
	// RequestsPerSecondByRule overrides the request rate for individual rules.
	RequestsPerSecondByRule map[string]float64
	// EnvVars lists environment variables provider expressions may read.
	EnvVars []string
}

func (o Options) runtimeOptions() provider.RuntimeOptions {
	return provider.RuntimeOptions{
		Debug: o.Debug, Timeout: o.Timeout,
		MaxRequestsPerTarget:    o.MaxRequestsPerTarget,
		RequestsPerSecond:       o.RequestsPerSecond,
		RequestsPerSecondByRule: o.RequestsPerSecondByRule,
		EnvVars:                 o.EnvVars,
	}
}

type programs struct {
	validation exprruntime.Program
	analysis   exprruntime.Program
}

// Validator owns an immutable configuration snapshot and a thread-safe cache
// of compiled provider expressions. Construct one with NewValidator.
type Validator struct {
	rules    map[string]config.Rule
	options  Options
	runtime  *exprruntime.Runtime
	mu       sync.Mutex
	programs map[string]programs
}

// NewValidator checks cfg and options and snapshots the rule inputs it uses.
// Provider expressions compile lazily; construction sends no requests and
// starts no workers. Detection regexes are checked by config validation but
// are never used to match credential input.
func NewValidator(cfg *config.Config, options Options) (*Validator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	options.RequestsPerSecondByRule = maps.Clone(options.RequestsPerSecondByRule)
	options.EnvVars = slices.Clone(options.EnvVars)
	runtime, err := provider.NewRuntime(options.runtimeOptions())
	if err != nil {
		return nil, err
	}
	rules := make(map[string]config.Rule, len(cfg.Rules))
	for _, source := range cfg.Rules {
		rule := source
		rule.Tags = slices.Clone(source.Tags)
		rule.Keywords = slices.Clone(source.Keywords)
		rule.Components = make([]*config.Component, len(source.Components))
		for i, component := range source.Components {
			copy := *component
			rule.Components[i] = &copy
		}
		rules[rule.ID] = rule
	}
	return &Validator{rules: rules, options: options, runtime: runtime, programs: make(map[string]programs)}, nil
}

func (v *Validator) programsFor(rule config.Rule) (programs, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.programs[rule.ID]; ok {
		return p, nil
	}
	p := programs{}
	var err error
	p.validation, err = v.runtime.CompileValidation(rule.ValidateExpr)
	if err != nil {
		return p, fmt.Errorf("compiling rule %s validation: %w", rule.ID, err)
	}
	if v.options.Analysis && rule.AnalyzeExpr != "" {
		p.analysis, err = v.runtime.CompileAnalysis(rule.AnalyzeExpr)
		if err != nil {
			return p, fmt.Errorf("compiling rule %s analysis: %w", rule.ID, err)
		}
	}
	v.programs[rule.ID] = p
	return p, nil
}
