package validate

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/report"
)

// validationJob is the internal unit of work for the pool.
type validationJob struct {
	finding  report.Finding
	program  exprruntime.Program
	captures map[string]string
}

// Pool manages a set of workers that validate findings asynchronously.
type Pool struct {
	runtime *exprruntime.Runtime
	cache   *Cache
	ctx     context.Context
	Debug   bool

	// one job per to-be-validated finding
	jobs chan validationJob
	wg   sync.WaitGroup

	// Emit receives fully-resolved, enriched findings.
	// Pool never synchronizes or retries around this callback; callers must make
	// it safe for concurrent worker use.
	Emit func(report.Finding)
}

// NewPool creates a validation pool with the given number of workers.
func NewPool(workers int, runtime *exprruntime.Runtime) *Pool {
	return NewPoolContext(context.Background(), workers, runtime)
}

// NewPoolContext creates a validation pool whose evaluations and request-limit
// waits are canceled with ctx.
func NewPoolContext(ctx context.Context, workers int, runtime *exprruntime.Runtime) *Pool {
	if workers <= 0 {
		workers = 10
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p := &Pool{
		runtime: runtime,
		cache:   NewCache(),
		ctx:     ctx,
		jobs:    make(chan validationJob, workers*10),
	}

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	return p
}

// Submit queues a job for validation. ComponentSets (if any) are already on the finding.
func (p *Pool) Submit(finding report.Finding, program exprruntime.Program) {
	_ = p.SubmitContext(context.Background(), finding, program)
}

// SubmitContext queues a job for validation unless the provided context has
// already been canceled.
func (p *Pool) SubmitContext(ctx context.Context, finding report.Finding, program exprruntime.Program) error {
	job := validationJob{
		finding:  finding,
		program:  program,
		captures: finding.CaptureGroups,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.jobs <- job:
		return nil
	}
}

// Close signals that no more jobs will be submitted and waits for all workers
// to finish.
func (p *Pool) Close() {
	close(p.jobs)
	p.wg.Wait()
}

// Stats returns cache hit/miss counts. Must be called after Close().
func (p *Pool) Stats() (hits, misses uint64) {
	return p.cache.Hits(), p.cache.Misses()
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for job := range p.jobs {
		f := job.finding

		if len(f.ComponentSets) == 0 {
			// Simple path: no matched components, validate the secret with its own captures.
			result, err := p.evalWithCaptures(job.program, job.finding.RuleID, job.finding.Secret, f.ToExprMap(), job.captures, f.Attributes)
			if err != nil {
				f.ValidationStatus = report.ValidationStatusError
				f.ValidationReason = err.Error()
			} else {
				f.ValidationStatus = result.Status
				f.ValidationReason = result.Reason
				f.ValidationMeta = result.Metadata
			}
			if p.Emit != nil {
				p.Emit(f)
			}
			continue
		}

		// Composite path: iterate pre-built component sets on the finding, validate
		// each, write per-set status, and roll up to a finding-level status.
		setResults := make(map[string]*Result, len(f.ComponentSets))
		var (
			overallStatus report.ValidationStatus
			bestResult    *Result
		)

		for i := range f.ComponentSets {
			set := &f.ComponentSets[i]

			// Build the structured component binding for this combination. Primary
			// named regex captures remain isolated in job.captures.
			components := make(map[string]any, len(set.Components))
			cacheComponents := make(map[string]cacheComponent, len(set.Components))
			for _, comp := range set.Components {
				captures := comp.CaptureGroups
				if captures == nil {
					captures = map[string]string{}
				}
				components[comp.RuleID] = map[string]any{
					"secret":   comp.Secret,
					"captures": captures,
				}
				cacheComponents[comp.RuleID] = cacheComponent{
					Secret:   comp.Secret,
					Captures: captures,
				}
			}

			cacheKey := CacheKey(job.finding.RuleID, job.finding.Secret, job.captures, cacheComponents)

			var result *Result
			if r, seen := setResults[cacheKey]; seen {
				result = r
			} else {
				var err error
				result, err = p.evalWithCacheKey(cacheKey, job.program, f.ToExprMap(), job.captures, components, f.Attributes)
				if err != nil {
					result = &Result{Status: report.ValidationStatusError, Reason: err.Error(), Metadata: map[string]any{}}
				}
				setResults[cacheKey] = result
			}

			// Write status onto this set.
			set.ValidationStatus = result.Status
			set.ValidationReason = result.Reason

			// Roll up finding-level status: pick the best (highest-priority) result.
			newStatus := BetterStatus(overallStatus, result.Status)
			if newStatus != overallStatus || bestResult == nil {
				overallStatus = newStatus
				bestResult = result
			}
		}

		// Set finding-level status from rollup.
		if bestResult != nil {
			f.ValidationStatus = overallStatus
			f.ValidationReason = bestResult.Reason
			f.ValidationMeta = bestResult.Metadata
		}

		// When at least one component set validates, keep only valid sets on the
		// emitted finding so reports are not cluttered with failed combinations.
		// We build a new slice so we do not compact a backing array that other
		// copies of this Finding may still reference.
		if slices.ContainsFunc(f.ComponentSets, func(s report.ComponentSet) bool {
			return s.ValidationStatus == report.ValidationStatusValid
		}) {
			validOnly := make([]report.ComponentSet, 0, len(f.ComponentSets))
			for _, s := range f.ComponentSets {
				if s.ValidationStatus == report.ValidationStatusValid {
					validOnly = append(validOnly, s)
				}
			}
			f.ComponentSets = validOnly
		}

		if p.Emit != nil {
			p.Emit(f)
		}
	}
}

// evalWithCaptures runs the validation program for the given secret and captures,
// using the cache to avoid duplicate HTTP requests. The secret is used only
// for cache keying; the program reads it from finding["secret"].
func (p *Pool) evalWithCaptures(program exprruntime.Program, ruleID, secret string, finding, captures, attributes map[string]string) (*Result, error) {
	cacheKey := CacheKey(ruleID, secret, captures, nil)
	return p.evalWithCacheKey(cacheKey, program, finding, captures, nil, attributes)
}

// evalWithCacheKey runs the validation program using the given pre-computed cache key.
func (p *Pool) evalWithCacheKey(cacheKey string, program exprruntime.Program, finding, captures map[string]string, components map[string]any, attributes map[string]string) (*Result, error) {
	if p.Debug {
		return p.evalProgram(program, finding, captures, components, attributes)
	}
	return p.cache.GetOrDo(cacheKey, func() (*Result, error) {
		return p.evalProgram(program, finding, captures, components, attributes)
	})
}

func (p *Pool) evalProgram(program exprruntime.Program, finding, captures map[string]string, components map[string]any, attributes map[string]string) (*Result, error) {
	result, evalErr := p.runtime.EvalValidationWithComponents(p.ctx, program, finding, captures, components, attributes, exprruntime.EvalOptions{Debug: p.Debug})
	if result.RequestLimitHit != nil {
		hit := result.RequestLimitHit
		metadata := map[string]any{
			"betterleaks_max_requests_hit":         true,
			"betterleaks_validation_target":        hit.Target,
			"betterleaks_validation_max_requests":  hit.MaxRequests,
			"betterleaks_validation_requests_sent": hit.RequestsSent,
		}
		if hit.RuleID != "" {
			metadata["betterleaks_validation_rule_id"] = hit.RuleID
		}
		maps.Copy(metadata, result.Debug)
		return &Result{
			Status: report.ValidationStatusNeedsValidation,
			Reason: fmt.Sprintf(
				"validation request limit reached for %s after %d requests",
				hit.Target,
				hit.RequestsSent,
			),
			Metadata: metadata,
		}, nil
	}
	if evalErr != nil {
		metadata := map[string]any{}
		maps.Copy(metadata, result.Debug)
		return &Result{Status: "error", Reason: evalErr.Error(), Metadata: metadata}, nil
	}
	r := ParseResult(result.Value)
	if len(result.Debug) > 0 {
		if r.Metadata == nil {
			r.Metadata = map[string]any{}
		}
		maps.Copy(r.Metadata, result.Debug)
	}
	return r, nil
}
