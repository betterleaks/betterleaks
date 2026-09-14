package provider

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/betterleaks/betterleaks/v2/internal/analyze"
	internalcache "github.com/betterleaks/betterleaks/v2/internal/cache"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/report"
)

// validationJob is the internal unit of work for the pool.
type validationJob struct {
	finding         report.Finding
	program         exprruntime.Program
	analysisProgram exprruntime.Program
	captures        map[string]string
}

// Pool manages a set of workers that validate findings asynchronously.
type Pool struct {
	runtime       *exprruntime.Runtime
	cache         *internalcache.Cache[*Result]
	analysisCache *internalcache.Cache[report.Analysis]
	ctx           context.Context
	Debug         bool

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
		cache: internalcache.NewWithStorePolicy(func(result *Result) bool {
			return result.Status != report.ValidationStatusError
		}),
		analysisCache: internalcache.New[report.Analysis](),
		ctx:           ctx,
		jobs:          make(chan validationJob, workers*10),
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
	return p.SubmitWithAnalysisContext(ctx, finding, program, nil)
}

// SubmitWithAnalysisContext queues validation and, when validation succeeds,
// an optional analysis program. Both stages run in the same bounded worker.
func (p *Pool) SubmitWithAnalysisContext(ctx context.Context, finding report.Finding, validationProgram, analysisProgram exprruntime.Program) error {
	job := validationJob{
		finding:         finding,
		program:         validationProgram,
		analysisProgram: analysisProgram,
		captures:        finding.Match.Captures,
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

// AnalysisStats returns analysis cache hit/miss counts. Must be called after
// Close.
func (p *Pool) AnalysisStats() (hits, misses uint64) {
	return p.analysisCache.Hits(), p.analysisCache.Misses()
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for job := range p.jobs {
		f := job.finding
		finding := map[string]string{"secret": f.Match.Value, "rule_id": f.RuleID}
		var attributes map[string]string
		secrets := f.CredentialValues()
		if len(f.ComponentSets) == 0 {
			key := CacheKey(f.RuleID, f.Match.Value, job.captures, nil)
			f.Analysis = p.resolveAnalysis(key, job, finding, attributes, nil, secrets, nil)
		} else {
			validationResults := make(map[string]*Result, len(f.ComponentSets))
			f.ComponentSets = slices.Clone(f.ComponentSets)
			f.Analysis = report.Analysis{}
			for i := range f.ComponentSets {
				set := &f.ComponentSets[i]
				components := make(map[string]any, len(set.Components))
				cacheComponents := make(map[string]cacheComponent, len(set.Components))
				for _, comp := range set.Components {
					if comp == nil {
						continue
					}
					captures := comp.Match.Captures
					if captures == nil {
						captures = map[string]string{}
					}
					components[comp.RuleID] = map[string]any{"secret": comp.Match.Value, "captures": captures}
					cacheComponents[comp.RuleID] = cacheComponent{Secret: comp.Match.Value, Captures: captures}
				}
				key := CacheKey(f.RuleID, f.Match.Value, job.captures, cacheComponents)
				set.Analysis = p.resolveAnalysis(key, job, finding, attributes, components, secrets, validationResults)
				// Select one complete result. Mixing liveness from one combination with
				// permissions or identity from another would describe a nonexistent credential.
				if betterAnalysis(f.Analysis, set.Analysis) {
					f.Analysis = set.Analysis
				}
			}
			// Preserve the existing reporting policy: successful combinations are
			// sufficient when at least one works; otherwise retain every attempted set.
			if slices.ContainsFunc(f.ComponentSets, func(s report.ComponentSet) bool {
				return s.Analysis.Status == report.ValidationStatusValid
			}) {
				valid := make([]report.ComponentSet, 0, len(f.ComponentSets))
				for _, set := range f.ComponentSets {
					if set.Analysis.Status == report.ValidationStatusValid {
						valid = append(valid, set)
					}
				}
				f.ComponentSets = valid
			}
		}
		if f.ComponentSetsTruncated && f.Analysis.Status != report.ValidationStatusValid {
			f.Analysis.Status = report.ValidationStatusNeedsValidation
			f.Analysis.StatusReason = "Component combination limit reached; credential search is incomplete"
		}

		if p.Emit != nil {
			p.Emit(f)
		}
	}
}

// resolveAnalysis keeps the two Expr stages private and publishes one result.
// Enrichment cannot replace liveness, including when it fails or hits a limit.
func (p *Pool) resolveAnalysis(key string, job validationJob, finding, attributes map[string]string, components map[string]any, secrets []string, validationResults map[string]*Result) report.Analysis {
	validation := validationResults[key]
	if validation == nil {
		var err error
		validation, err = p.evalWithCacheKey(key, job.program, finding, job.captures, components, attributes)
		if err != nil {
			validation = &Result{Status: report.ValidationStatusError, Reason: err.Error()}
		}
		// Repeated locations of the same component combination share even failures
		// within this finding. Later findings may retry transient provider errors.
		if validationResults != nil {
			validationResults[key] = validation
		}
	}
	var enrichment report.Analysis
	if validation.Status == report.ValidationStatusValid && job.analysisProgram != nil {
		enrichment = p.evalAnalysisWithCacheKey(key, job.analysisProgram, finding, job.captures, components, attributes, validation)
	}
	return report.SanitizeAnalysis(combineAnalysis(validation, enrichment), secrets)
}

// combineAnalysis keeps credential-state evidence separate from enrichment.
// Private validation analysis input never enters the public report.
func combineAnalysis(validation *Result, enrichment report.Analysis) report.Analysis {
	result := enrichment
	result.Status = validation.Status
	result.StatusReason = validation.Reason
	result.StatusMetadata = validation.Metadata
	result.Debug = nil
	if len(validation.Debug) > 0 || len(enrichment.Debug) > 0 {
		result.Debug = make(map[string]any, 2)
		if len(validation.Debug) > 0 {
			result.Debug["validation"] = validation.Debug
		}
		if len(enrichment.Debug) > 0 {
			result.Debug["analysis"] = enrichment.Debug
		}
	}
	return result
}

func (p *Pool) evalAnalysisWithCacheKey(cacheKey string, program exprruntime.Program, finding, captures map[string]string, components map[string]any, attributes map[string]string, validation *Result) report.Analysis {
	if p.Debug {
		result, err := p.evalAnalysisProgram(program, finding, captures, components, attributes, validation)
		if err != nil {
			result.Reason = err.Error()
			result.Severity = report.SeverityUnknown
		}
		return result
	}
	result, err := p.analysisCache.GetOrDo(cacheKey, func() (report.Analysis, error) {
		return p.evalAnalysisProgram(program, finding, captures, components, attributes, validation)
	})
	if err != nil {
		return report.Analysis{Reason: err.Error(), Severity: report.SeverityUnknown}
	}
	return result
}

func (p *Pool) evalAnalysisProgram(program exprruntime.Program, finding, captures map[string]string, components map[string]any, attributes map[string]string, validation *Result) (report.Analysis, error) {
	metadata := map[string]any{}
	analysis := map[string]any{}
	status := report.ValidationStatusNone
	reason := ""
	if validation != nil {
		metadata = validation.Metadata
		analysis = validation.Analysis
		status = validation.Status
		reason = validation.Reason
	}
	result, evalErr := p.runtime.EvalAnalysisWithComponents(
		p.ctx,
		program,
		finding,
		captures,
		components,
		attributes,
		map[string]any{
			"status":   string(status),
			"reason":   reason,
			"metadata": metadata,
			"analysis": analysis,
		},
		exprruntime.EvalOptions{Debug: p.Debug},
	)
	if result.RequestLimitHit != nil {
		hit := result.RequestLimitHit
		return report.Analysis{Debug: result.Debug}, fmt.Errorf(
			"analysis request limit reached for %s after %d requests",
			hit.Target,
			hit.RequestsSent,
		)
	}
	if evalErr != nil {
		return report.Analysis{Debug: result.Debug}, evalErr
	}
	analysisResult, err := analyze.ParseResult(result.Value)
	if err != nil {
		return report.Analysis{Debug: result.Debug}, err
	}
	analysisResult.Debug = result.Debug
	return analysisResult, nil
}

func betterAnalysis(current, candidate report.Analysis) bool {
	if candidate.IsZero() {
		return false
	}
	if current.IsZero() {
		return true
	}
	if candidate.Status != current.Status {
		return BetterStatus(current.Status, candidate.Status) == candidate.Status
	}
	candidateSeverity := analysisSeverityRank(candidate.Severity)
	currentSeverity := analysisSeverityRank(current.Severity)
	if candidateSeverity != currentSeverity {
		return candidateSeverity > currentSeverity
	}
	if (candidate.Reason == "") != (current.Reason == "") {
		return candidate.Reason == ""
	}
	if len(candidate.Capabilities) != len(current.Capabilities) {
		return len(candidate.Capabilities) > len(current.Capabilities)
	}
	return candidate.Identity != nil && current.Identity == nil
}

func analysisSeverityRank(severity report.Severity) int {
	switch severity {
	case report.SeverityHigh:
		return 3
	case report.SeverityMedium:
		return 2
	default:
		return 0
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
		return &Result{
			Status: report.ValidationStatusNeedsValidation,
			Reason: fmt.Sprintf(
				"validation request limit reached for %s after %d requests",
				hit.Target,
				hit.RequestsSent,
			),
			Metadata: metadata,
			Debug:    result.Debug,
		}, nil
	}
	if evalErr != nil {
		return &Result{Status: report.ValidationStatusError, Reason: evalErr.Error(), Debug: result.Debug}, nil
	}
	r := ParseResult(result.Value)
	r.Debug = result.Debug
	return r, nil
}
