package validate

import (
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/google/cel-go/cel"
)

// ValidationResult pairs a finding's fingerprint with its validation outcome.
type ValidationResult struct {
	Fingerprint string
	Status      string
	Reason      string
	Meta        map[string]any
}

// validationJob is the internal unit of work for the pool.
type validationJob struct {
	groupID  string
	finding  report.Finding
	program  any // cel.Program
	captures map[string]string
	required map[string]string
}

// statusPriority defines the preference order when merging results for the same
// fingerprint. Lower number = higher priority ("valid" wins over everything).
var statusPriority = map[string]int{
	"valid":   0,
	"invalid": 1,
	"revoked": 2,
	"unknown": 3,
	"error":   4,
}

// fingerprintState tracks combo results for a single fingerprint.
type fingerprintState struct {
	finding  report.Finding
	best     ValidationResult
	hasBest  bool
	pending  int
	resolved bool
}

// Pool manages a set of workers that validate findings asynchronously.
type Pool struct {
	env   *Environment
	cache *Cache
	jobs  chan validationJob
	wg    sync.WaitGroup

	nextGroup atomic.Uint64

	mu     sync.Mutex
	states map[string]*fingerprintState

	// FindingsCh receives fully-resolved, enriched findings. It is owned and
	// closed by the Detector; Pool only sends to it.
	FindingsCh chan<- report.Finding
}

// NewGroupID returns a unique opaque ID to be shared across all Submit calls
// for a single finding (e.g. all combo expansions of one multi-part rule).
func (p *Pool) NewGroupID() string {
	return strconv.FormatUint(p.nextGroup.Add(1), 10)
}

// NewPool creates a validation pool with the given number of workers.
func NewPool(workers int, env *Environment) *Pool {
	if workers <= 0 {
		workers = 10
	}
	p := &Pool{
		env:    env,
		cache:  NewCache(),
		jobs:   make(chan validationJob, workers*10),
		states: make(map[string]*fingerprintState),
	}

	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	return p
}

// Submit queues a combo job for validation under groupID. count is the total
// number of Submit calls sharing this groupID (1 for simple findings, N for
// combo expansion). All Submit calls for the same group must pass the same
// count and finding values. Use NewGroupID to allocate a fresh groupID.
func (p *Pool) Submit(groupID string, finding report.Finding, program any, captures map[string]string, required map[string]string, count int) {
	p.mu.Lock()
	if _, ok := p.states[groupID]; !ok {
		p.states[groupID] = &fingerprintState{pending: count, finding: finding}
	}
	p.mu.Unlock()

	p.jobs <- validationJob{
		groupID:  groupID,
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
		vr := ValidationResult{
			Fingerprint: job.finding.Fingerprint,
			Meta:        map[string]any{},
		}

		prg, ok := job.program.(cel.Program)
		if !ok {
			logging.Warn().
				Str("rule", job.finding.RuleID).
				Msg("validation job has invalid program type")
			vr.Status = "error"
			vr.Reason = "invalid CEL program type"
		} else {
			cacheKey := CacheKey(job.finding.RuleID, job.finding.Secret, job.required)
			// Merge required rule secrets into captures so the CEL
			// program can reference them (e.g. captures["rule-id"]).
			merged := job.captures
			if len(job.required) > 0 {
				merged = make(map[string]string, len(job.captures)+len(job.required))
				for k, v := range job.captures {
					merged[k] = v
				}
				for k, v := range job.required {
					merged[k] = v
				}
			}
			result, err := p.cache.GetOrDo(cacheKey, func() (*Result, error) {
				return p.env.Eval(prg, job.finding.Secret, merged)
			})
			if err != nil {
				vr.Status = "error"
				vr.Reason = err.Error()
			} else {
				vr.Status = result.Status
				vr.Reason = result.Reason
				vr.Meta = result.Metadata
			}
		}

		p.mu.Lock()
		state := p.states[job.groupID]
		state.pending--

		// Update best if this result has higher priority.
		newPri := statusPriority[vr.Status]
		if !state.hasBest || newPri < statusPriority[state.best.Status] {
			state.best = vr
			state.hasBest = true
		}

		// Resolve when all combos done OR "valid" short-circuits.
		shouldFire := false
		if !state.resolved && (state.pending <= 0 || vr.Status == "valid") {
			state.resolved = true
			shouldFire = true
		}
		best := state.best
		f := state.finding
		p.mu.Unlock()

		if shouldFire && p.FindingsCh != nil {
			f.ValidationStatus = best.Status
			f.ValidationReason = best.Reason
			f.ValidationMeta = best.Meta
			p.FindingsCh <- f
		}
	}
}
