package validate

import (
	"maps"
	"sync"

	"github.com/betterleaks/betterleaks/celenv"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/google/cel-go/cel"
)

// validationJob is the internal unit of work for the pool.
type validationJob struct {
	finding report.Finding
	program any // cel.Program

	// todo rename to componentCaptures?
	captures map[string]string
	required map[string]string
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
func (p *Pool) Submit(finding report.Finding, program any, captures map[string]string, required map[string]string) {
	p.jobs <- validationJob{
		finding:  finding,
		program:  program,
		captures: captures,
		required: required,
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
		prg, ok := job.program.(cel.Program)
		if !ok {
			logging.Fatal().Str("rule", job.finding.RuleID).Msg("invalid CEL program")
		}

		merged := job.captures
		if len(job.required) > 0 {
			merged = make(map[string]string, len(job.captures)+len(job.required))
			maps.Copy(merged, job.captures)
			maps.Copy(merged, job.required)
		}

		cacheKey := CacheKey(job.finding.RuleID, job.finding.Secret, merged)
		result, err := p.cache.GetOrDo(cacheKey, func() (*Result, error) {
			val, evalErr := p.env.Eval(prg, job.finding.Secret, merged)
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

		f := job.finding
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
	}
}
