package analyze

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
)

// Producer supplies findings to a bounded provider queue. It must honor ctx,
// stop when yield returns an error, and finish all calls to yield before
// returning. Calls to yield may be concurrent. Finding inputs must remain
// unchanged until the operation completes.
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
			// Rechecks replace old conclusions. Component results belong to this
			// evaluation, not the caller's backing slice.
			f.Analysis = report.Analysis{}
			f.ComponentSets = slices.Clone(f.ComponentSets)
			for i := range f.ComponentSets {
				f.ComponentSets[i].Analysis = report.Analysis{}
			}
			if programs.validation == nil {
				return emit(f)
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
