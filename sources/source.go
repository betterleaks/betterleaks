package sources

import (
	"context"
	"runtime"
)

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment
type FragmentsFunc func(fragment Fragment, err error) error

// SkipFunc decides whether to skip a fragment based on its attributes.
// Returns true to skip (discard), false to keep.
// Used by sources as a callback to decouple path/commit filtering from config.
type SkipFunc func(attrs map[string]string) bool

// Source is a thing that can yield fragments
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source. A source must not mutate a fragment or its
	// attributes after yield accepts it.
	Fragments(ctx context.Context, yield FragmentsFunc) error
}

func workerCount(configured, fallback int) int {
	if configured > 0 {
		return configured
	}
	return fallback
}

func automaticJobs() int {
	return max(runtime.GOMAXPROCS(0), 1)
}

func automaticFileJobs() int {
	processorJobs := automaticJobs()
	return max(processorJobs, min(processorJobs*4, 40))
}

func automaticObjectJobs() int {
	return automaticJobs() * 2
}

const maxProviderTargetJobs = 4

func automaticProviderJobs() int {
	return min(automaticJobs(), maxProviderTargetJobs)
}

func providerTargetJobs(jobs int, singleTarget bool) int {
	if singleTarget {
		return 1
	}
	return min(jobs, maxProviderTargetJobs)
}

// jobBudget bounds leaf source work across nested sources. Provider target
// goroutines do not hold a slot while waiting for their Git or object work, so
// nested scans can share this budget without deadlocking.
type jobBudget struct {
	limit int
	slots chan struct{}
}

func newJobBudget(jobs int) *jobBudget {
	jobs = max(jobs, 1)
	return &jobBudget{
		limit: jobs,
		slots: make(chan struct{}, jobs),
	}
}

func jobsWithinBudget(configured, fallback int, existing *jobBudget) int {
	jobs := workerCount(configured, fallback)
	if existing != nil {
		jobs = min(jobs, existing.limit)
	}
	return jobs
}

func ensureJobBudget(configured, fallback int, existing *jobBudget) (int, *jobBudget) {
	jobs := jobsWithinBudget(configured, fallback, existing)
	if existing != nil {
		return jobs, existing
	}
	return jobs, newJobBudget(jobs)
}

func (b *jobBudget) run(ctx context.Context, fn func() error) error {
	if b == nil {
		return fn()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case b.slots <- struct{}{}:
	}
	defer func() { <-b.slots }()
	return fn()
}
