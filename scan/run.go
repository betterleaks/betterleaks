package scan

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Result is one finding or recoverable error emitted by [Scanner.Run].
type Result struct {
	// Finding is populated when Err is nil.
	Finding report.Finding
	// Err is a recoverable source or pipeline error.
	Err error
}

// ScanSummary describes the work completed by one scan.
type ScanSummary struct {
	// BytesInspected excludes fragments rejected by the scanner prefilter.
	BytesInspected uint64
	// Findings is the number of findings that passed output filters.
	Findings int
}

// Handler consumes one finding. Scan invokes handlers synchronously and never
// concurrently. Returning an error stops the scan. Handlers may start another
// scan with an independent source.
type Handler func(report.Finding) error

// Run executes the pipeline and yields findings and recoverable source errors.
// Findings are not retained. Result order is not guaranteed. Concurrent calls
// on the same Scanner are safe with independent sources.
func (d *Scanner) Run(ctx context.Context, source sources.Source) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		if d == nil {
			_ = yield(Result{Err: errors.New("scanner is nil")})
			return
		}
		_ = d.run(ctx, source, yield)
	}
}

// Scan executes the pipeline, passes each finding to handler, and returns a
// per-call summary. Recoverable source errors are joined. Returning an error
// from handler stops the scan. A nil handler discards findings.
func (d *Scanner) Scan(ctx context.Context, source sources.Source, handler Handler) (ScanSummary, error) {
	if d == nil {
		return ScanSummary{}, errors.New("scanner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var scanErr error
	summary := d.run(ctx, source, func(result Result) bool {
		if result.Err != nil {
			scanErr = errors.Join(scanErr, result.Err)
			return true
		}
		if handler != nil {
			if err := handler(result.Finding); err != nil {
				scanErr = errors.Join(scanErr, fmt.Errorf("handle finding: %w", err))
				return false
			}
		}
		return true
	})
	if err := ctx.Err(); err != nil && !errors.Is(scanErr, err) {
		scanErr = errors.Join(scanErr, err)
	}
	return summary, scanErr
}

type scanState struct {
	bytes       atomic.Uint64
	summary     ScanSummary
	ruleTimings *ruletiming.Collector
}

func (d *Scanner) run(ctx context.Context, source sources.Source, yield func(Result) bool) (summary ScanSummary) {
	state := scanState{}
	if source == nil {
		_ = yield(Result{Err: errors.New("pipeline: nil source")})
		return state.summary
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state.ruleTimings = ruletiming.FromContext(ctx)

	runCtx, cancel := context.WithCancel(ctx)
	workerCount := d.jobCount()
	resultsCh := make(chan Result, workerCount)
	defer func() {
		cancel()
		for range resultsCh {
		}
		state.summary.BytesInspected = state.bytes.Load()
		summary = state.summary
	}()

	emit := func(result Result) error {
		select {
		case <-runCtx.Done():
			return errStopIteration
		case resultsCh <- result:
			return nil
		}
	}
	go func() {
		defer close(resultsCh)

		fragmentsCh := make(chan sources.Fragment, workerCount)
		var workers sync.WaitGroup
		workers.Add(workerCount)
		for range workerCount {
			go func() {
				defer workers.Done()
				for fragment := range fragmentsCh {
					if err := d.scanFragment(runCtx, fragment, emit, &state); err != nil {
						if !isPipelineStop(err) {
							_ = emit(Result{Err: err})
						}
						cancel()
						return
					}
				}
			}()
		}

		sourceErr := source.Fragments(runCtx, func(fragment sources.Fragment, fragmentErr error) error {
			if fragmentErr != nil {
				if isPipelineStop(fragmentErr) {
					return errStopIteration
				}
				return emit(Result{Err: fragmentErr})
			}
			if len(fragment.Raw) == 0 && fragment.Attr(sources.AttrPath) == "" {
				return nil
			}
			select {
			case <-runCtx.Done():
				return errStopIteration
			case fragmentsCh <- fragment:
				return nil
			}
		})
		close(fragmentsCh)
		workers.Wait()

		if sourceErr != nil && !isPipelineStop(sourceErr) {
			_ = emit(Result{Err: sourceErr})
		}
	}()

	for result := range resultsCh {
		if isPipelineStop(result.Err) {
			continue
		}
		if result.Err == nil {
			state.summary.Findings++
		}
		if !yield(result) {
			return state.summary
		}
	}
	return state.summary
}

func isPipelineStop(err error) bool {
	return errors.Is(err, errStopIteration) || errors.Is(err, context.Canceled)
}

func (d *Scanner) jobCount() int {
	if d.jobs > 0 {
		return d.jobs
	}
	return max(runtime.GOMAXPROCS(0), 1)
}

func (d *Scanner) scanFragment(
	ctx context.Context,
	fragment sources.Fragment,
	emit func(Result) error,
	state *scanState,
) error {
	for _, finding := range d.detectFragmentWithState(ctx, fragment, state) {
		if err := emit(Result{Finding: finding}); err != nil {
			return err
		}
	}
	return nil
}
