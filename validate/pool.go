package validate

import (
	"maps"
	"sync"

	"github.com/betterleaks/betterleaks/celenv"
	"github.com/betterleaks/betterleaks/report"
	"github.com/google/cel-go/cel"
)

// validationJob is the internal unit of work for the pool.
type validationJob struct {
	finding  report.Finding
	program  cel.Program
	captures map[string]string
}

// Pool manages a set of workers that validate findings asynchronously.
type Pool struct {
	env   *celenv.Environment
	cache *Cache

	// one job per to-be-validated finding
	jobs chan validationJob
	wg   sync.WaitGroup

	// Emit receives fully-resolved, enriched findings.
	// Pool never synchronizes or retries around this callback; callers must make
	// it safe for concurrent worker use.
	Emit func(report.Finding)
}

// NewPool creates a validation pool with the given number of workers.
func NewPool(workers int, env *celenv.Environment) *Pool {
	if workers <= 0 {
		workers = 10
	}
	p := &Pool{
		env:   env,
		cache: NewCache(),
		jobs:  make(chan validationJob, workers*10),
	}

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	return p
}

// Submit queues a job for validation. RequiredSets (if any) are already on the finding.
func (p *Pool) Submit(finding report.Finding, program cel.Program, captures map[string]string) {
	p.jobs <- validationJob{
		finding:  finding,
		program:  program,
		captures: captures,
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

		if len(f.RequiredSets) == 0 {
			// Simple path: no required components, validate the secret with its own captures.
			result, err := p.evalWithCaptures(job.program, job.finding.RuleID, job.finding.Secret, job.captures)
			if err != nil {
				f.ValidationStatus = "error"
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

		// Composite path: iterate pre-built required sets on the finding, validate
		// each, write per-set status, and roll up to a finding-level status.
		setResults := make(map[string]*Result, len(f.RequiredSets))
		var (
			overallStatus string
			bestResult    *Result
		)

		for i := range f.RequiredSets {
			set := &f.RequiredSets[i]

			// Build merged captures from the set's components.
			merged := make(map[string]string, len(job.captures)+len(set.Components)*2)
			maps.Copy(merged, job.captures)
			for _, comp := range set.Components {
				merged[comp.RuleID] = comp.Secret
				for name, val := range comp.CaptureGroups {
					merged[comp.RuleID+":"+name] = val
				}
			}

			cacheKey := CacheKey(job.finding.RuleID, job.finding.Secret, merged)

			var result *Result
			if r, seen := setResults[cacheKey]; seen {
				result = r
			} else {
				var err error
				result, err = p.evalWithCacheKey(cacheKey, job.program, job.finding.Secret, merged)
				if err != nil {
					result = &Result{Status: "error", Reason: err.Error(), Metadata: map[string]any{}}
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

		if p.Emit != nil {
			p.Emit(f)
		}
	}
}

// evalWithCaptures runs the CEL program for the given secret and captures,
// using the cache to avoid duplicate HTTP requests.
func (p *Pool) evalWithCaptures(program cel.Program, ruleID, secret string, captures map[string]string) (*Result, error) {
	cacheKey := CacheKey(ruleID, secret, captures)
	return p.evalWithCacheKey(cacheKey, program, secret, captures)
}

// evalWithCacheKey runs the CEL program using the given pre-computed cache key.
func (p *Pool) evalWithCacheKey(cacheKey string, program cel.Program, secret string, captures map[string]string) (*Result, error) {
	return p.cache.GetOrDo(cacheKey, func() (*Result, error) {
		val, evalErr := p.env.Eval(program, secret, captures)
		if evalErr != nil {
			return &Result{Status: "error", Reason: evalErr.Error(), Metadata: map[string]any{}}, nil
		}
		r := ParseResult(val)
		if p.env.DebugResponse {
			if debugMeta := p.env.DebugMeta(); len(debugMeta) > 0 {
				if r.Metadata == nil {
					r.Metadata = make(map[string]any)
				}
				maps.Copy(r.Metadata, debugMeta)
			}
		}
		return r, nil
	})
}
