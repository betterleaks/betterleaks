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
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/limits"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
)

type programs struct {
	validation             exprruntime.Program
	analysis               exprruntime.Program
	requirements           credential.Requirements
	validationRequirements credential.Requirements
	analysisRequirements   credential.Requirements
	requirementsReady      bool
}

// Analyzer owns an immutable rule snapshot and compiled provider programs.
// Calls may run concurrently. Each operation gets fresh provider workers,
// result caches, and request limits; compiled programs are shared across calls.
// Construction starts no workers and sends no requests.
type Analyzer struct {
	rules           map[string]config.Rule
	primaryCaptures map[string]string
	options         options
	runtime         *exprruntime.Runtime
	mu              sync.Mutex
	programs        map[string]programs
	hasValidation   bool
	hasAnalysis     bool
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
	a := &Analyzer{rules: make(map[string]config.Rule, len(cfg.Rules)), primaryCaptures: make(map[string]string, len(cfg.Rules)), options: settings, runtime: runtime, programs: make(map[string]programs)}
	for _, source := range cfg.Rules {
		rule := source
		rule.Tags = slices.Clone(source.Tags)
		rule.Keywords = slices.Clone(source.Keywords)
		rule.Components = slices.Clone(source.Components)
		a.rules[rule.ID] = rule
		a.primaryCaptures[rule.ID] = credential.PrimaryCapture(rule)
		a.hasValidation = a.hasValidation || rule.ValidateExpr != ""
		a.hasAnalysis = a.hasAnalysis || (rule.ValidateExpr != "" && rule.AnalyzeExpr != "")
	}
	if settings.precompile {
		for _, source := range cfg.Rules {
			if _, err := a.programsFor(a.rules[source.ID], true); err != nil {
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
	if !p.requirementsReady {
		p.validationRequirements = a.requirementsFor(rule, false)
		p.analysisRequirements = a.requirementsFor(rule, true)
		p.requirementsReady = true
	}
	p.requirements = p.validationRequirements
	if analysis {
		p.requirements = p.analysisRequirements
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
// failures are represented by Analysis.Status.
func (a *Analyzer) Validate(ctx context.Context, finding report.Finding) (report.Finding, error) {
	return a.resolve(ctx, finding, false)
}

// Analyze validates a finding and resolves identity and permissions when valid.
// Provider expressions read only credential values and captures. Source context
// and provenance pass through unchanged and never affect provider resolution.
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

// ValidateCredential checks an already-extracted credential without running
// analysis. It bypasses discovery and scan policy. Supplied secret material is
// sanitized in the returned report. Each call has independent request limits.
func (a *Analyzer) ValidateCredential(ctx context.Context, input credential.Input) (report.CredentialReport, error) {
	return a.resolveCredential(ctx, input, false)
}

// AnalyzeCredential validates a credential, then resolves its identity and
// permissions when valid. Validation's private output is available to analysis
// but never exported in the report. Calls may run concurrently.
func (a *Analyzer) AnalyzeCredential(ctx context.Context, input credential.Input) (report.CredentialReport, error) {
	return a.resolveCredential(ctx, input, true)
}

func (a *Analyzer) resolveCredential(ctx context.Context, input credential.Input, analysis bool) (report.CredentialReport, error) {
	if ctx == nil {
		return report.CredentialReport{}, errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return report.CredentialReport{}, err
	}
	if a == nil || a.runtime == nil {
		return report.CredentialReport{}, errors.New("analyzer must be constructed with New")
	}
	rule, ok := a.rules[input.RuleID]
	if !ok {
		return report.CredentialReport{}, fmt.Errorf("rule %q not found in config", input.RuleID)
	}
	if strings.TrimSpace(rule.ValidateExpr) == "" {
		return report.CredentialReport{}, fmt.Errorf("rule %q does not define validation", input.RuleID)
	}
	finding := input.Finding(rule)
	secrets := finding.CredentialValues()
	result, err := a.resolve(ctx, finding, analysis)
	if err != nil {
		return report.CredentialReport{}, err
	}
	return report.NewCredentialReport(result, secrets), nil
}

// Producer supplies findings to a bounded provider queue. It must honor ctx,
// stop when yield returns an error, and finish all calls to yield before
// returning. Calls to yield may be concurrent. After yield returns, the producer
// may reuse or mutate its input; Analyzer snapshots mutable finding data before
// accepting it.
type Producer func(ctx context.Context, yield func(report.Finding) error) error

// AnalyzeStream validates and analyzes findings with independent provider
// workers. Results reach handler serially in completion order. Returning an
// error cancels the producer and provider requests and waits for them to stop.
// A nil handler discards results. The operation shares result caches and request
// limits across all inputs; both are discarded when it ends.
func (a *Analyzer) AnalyzeStream(ctx context.Context, produce Producer, handler func(report.Finding) error) error {
	return a.stream(ctx, produce, handler, true, 0)
}

// ValidateStream checks liveness without compiling or running analysis programs.
func (a *Analyzer) ValidateStream(ctx context.Context, produce Producer, handler func(report.Finding) error) error {
	return a.stream(ctx, produce, handler, false, 0)
}

func (a *Analyzer) stream(ctx context.Context, produce Producer, handler func(report.Finding) error, analysis bool, workers int) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if a == nil || a.runtime == nil {
		return errors.New("analyzer must be constructed with New")
	}
	if produce == nil {
		return errors.New("finding producer must not be nil")
	}
	if workers == 0 {
		workers = a.options.workers
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	pool, err := provider.NewConfiguredPool(runCtx, workers, a.options.RuntimeOptions)
	if err != nil {
		return err
	}
	results := make(chan report.Finding, workers)
	emit := func(f report.Finding) error {
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		case results <- f:
			return nil
		}
	}
	pool.Emit = func(f report.Finding) { _ = emit(f) }
	var producerErr error
	go func() {
		defer close(results)
		producerErr = produce(runCtx, func(f report.Finding) error {
			if err := runCtx.Err(); err != nil {
				return err
			}
			rule, ok := a.rules[f.RuleID]
			if !ok {
				return fmt.Errorf("rule %q not found in config", f.RuleID)
			}
			programs, err := a.programsFor(rule, analysis)
			if err != nil {
				return err
			}
			if len(f.ComponentSets) > maxComponentSets {
				return fmt.Errorf("component sets exceed limit of %d", maxComponentSets)
			}
			// Snapshot before enqueueing: callers regain ownership when yield returns.
			f = f.Clone()
			f.Analysis = report.Analysis{}
			for i := range f.ComponentSets {
				f.ComponentSets[i].Analysis = report.Analysis{}
			}
			if programs.validation == nil {
				return emit(f)
			}
			if err := credential.ValidateFinding(&f, rule, programs.requirements, a.rules, a.primaryCaptures); err != nil {
				return fmt.Errorf("rule %q: %w", rule.ID, err)
			}

			return pool.SubmitWithAnalysisContext(runCtx, f, programs.validation, programs.analysis)
		})
		pool.Close()
		if a.options.logger.Enabled(runCtx, slog.LevelDebug) {
			hits, misses := pool.Stats()
			a.options.logger.Debug("validation cache stats", "evaluations", misses, "cache_hits", hits)
			if analysis {
				hits, misses := pool.AnalysisStats()
				a.options.logger.Debug("analysis cache stats", "evaluations", misses, "cache_hits", hits)
			}
		}
	}()
	// Always drain so cancellation, including a failed handler, waits for all
	// workers and the producer. Closing results synchronizes producerErr.
	var handlerErr error
	for finding := range results {
		if handlerErr != nil || ctx.Err() != nil {
			continue
		}
		if handler != nil {
			if err := handler(finding); err != nil {
				handlerErr = fmt.Errorf("handle finding: %w", err)
				cancel()
			}
		}
	}
	return errors.Join(handlerErr, producerErr, ctx.Err())
}

// Requirements returns the inputs needed for validation and analysis. The
// returned slices are independent of the Analyzer's configuration.
func (a *Analyzer) Requirements(ruleID string) (credential.Requirements, error) {
	return a.ruleRequirements(ruleID, true)
}

// ValidationRequirements returns only the inputs needed to check liveness.
func (a *Analyzer) ValidationRequirements(ruleID string) (credential.Requirements, error) {
	return a.ruleRequirements(ruleID, false)
}

func (a *Analyzer) ruleRequirements(ruleID string, analysis bool) (credential.Requirements, error) {
	if a == nil || a.runtime == nil {
		return credential.Requirements{}, fmt.Errorf("analyzer must be constructed with New")
	}
	rule, ok := a.rules[ruleID]
	if !ok {
		return credential.Requirements{}, fmt.Errorf("rule %q not found in config", ruleID)
	}
	return a.requirementsFor(rule, analysis), nil
}

func (a *Analyzer) requirementsFor(rule config.Rule, analysis bool) credential.Requirements {
	expressions := []string{rule.ValidateExpr}
	if analysis {
		expressions = append(expressions, rule.AnalyzeExpr)
	}
	return credential.RequirementsFor(rule, a.primaryCaptures, expressions...)
}

// Keep the Analyzer's public handoff bounded as well as Scanner discovery.
const maxComponentSets = limits.ComponentSets
