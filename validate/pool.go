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
	finding          report.Finding
	program          cel.Program
	captures         map[string]string
	requiredFindings []*report.RequiredFinding
}

// Pool manages a set of workers that validate findings asynchronously.
type Pool struct {
	env   *celenv.Environment
	cache *Cache

	// one job per to-be-validated finding
	jobs chan validationJob
	wg   sync.WaitGroup

	// FindingsCh receives fully-resolved, enriched findings. It is owned and
	// closed by the Detector; Pool only sends to it.
	FindingsCh chan<- report.Finding
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

// Submit queues a job for validation.
// requiredFindings should be nil for simple (non-composite) rules, or the slice
// of required components for composite rules. The worker expands and deduplicates
// combos internally, annotates each RequiredFinding with its per-component
// ValidationStatus, and emits exactly one enriched finding.
func (p *Pool) Submit(finding report.Finding, program cel.Program, captures map[string]string, requiredFindings []*report.RequiredFinding) {
	p.jobs <- validationJob{
		finding:          finding,
		program:          program,
		captures:         captures,
		requiredFindings: requiredFindings,
	}
}

// Close signals that no more jobs will be submitted and waits for all workers
// to finish. It does NOT close FindingsCh — the Detector owns that channel.
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

		if len(job.requiredFindings) == 0 {
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
			if p.FindingsCh != nil {
				p.FindingsCh <- f
			}
			continue
		}

		// Composite path: expand required findings into combos, validate each unique
		// combo (deduplicated by cache key), annotate per-component ValidationStatus,
		// roll up to a single finding-level status, emit ONE finding.
		combos := ExpandRequired(job.requiredFindings)

		// Build a set of valid ruleIDs so we can skip capture-group entries
		// ("ruleID:captureName" keys) when annotating components.
		ruleIDSet := make(map[string]struct{}, len(job.requiredFindings))
		for _, req := range job.requiredFindings {
			ruleIDSet[req.RuleID] = struct{}{}
		}

		// Maps (ruleID, secret) → best status seen across all combos using that secret.
		type ruleSecret struct{ ruleID, secret string }
		bestByComponent := make(map[ruleSecret]string)

		// comboResults deduplicates combos that hash to the same cache key
		// (e.g. 4 copies of the same access key produce 4 identical combos).
		comboResults := make(map[string]*Result, len(combos))
		var (
			overallStatus string
			bestResult    *Result
		)

		for _, combo := range combos {
			merged := make(map[string]string, len(job.captures)+len(combo))
			maps.Copy(merged, job.captures)
			maps.Copy(merged, combo)

			cacheKey := CacheKey(job.finding.RuleID, job.finding.Secret, merged)

			var result *Result
			if r, seen := comboResults[cacheKey]; seen {
				// Identical combo already evaluated — reuse the result.
				result = r
			} else {
				var err error
				result, err = p.evalWithCacheKey(cacheKey, job.program, job.finding.Secret, merged)
				if err != nil {
					result = &Result{Status: "error", Reason: err.Error(), Metadata: map[string]any{}}
				}
				comboResults[cacheKey] = result
			}

			// Roll up finding-level status: pick the best (highest-priority) result.
			newStatus := BetterStatus(overallStatus, result.Status)
			if newStatus != overallStatus || bestResult == nil {
				overallStatus = newStatus
				bestResult = result
			}

			// Annotate each plain ruleID component in this combo.
			for ruleID, secret := range combo {
				if _, isRuleID := ruleIDSet[ruleID]; !isRuleID {
					continue // skip "ruleID:captureName" entries
				}
				rs := ruleSecret{ruleID, secret}
				bestByComponent[rs] = BetterStatus(bestByComponent[rs], result.Status)
			}
		}

		// Write per-component status back to each RequiredFinding.
		for _, req := range job.requiredFindings {
			rs := ruleSecret{req.RuleID, req.Secret}
			if status, ok := bestByComponent[rs]; ok {
				req.ValidationStatus = status
			}
		}

		// Set finding-level status from rollup.
		if bestResult != nil {
			f.ValidationStatus = overallStatus
			f.ValidationReason = bestResult.Reason
			f.ValidationMeta = bestResult.Metadata
		}

		if p.FindingsCh != nil {
			p.FindingsCh <- f
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
