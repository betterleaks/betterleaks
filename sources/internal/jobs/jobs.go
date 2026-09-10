package jobs

import (
	"context"
	"runtime"
)

func WorkerCount(configured, fallback int) int {
	if configured > 0 {
		return configured
	}
	return fallback
}

func Automatic() int {
	return max(runtime.GOMAXPROCS(0), 1)
}

func AutomaticGit() int {
	// Each history worker owns a Git process as well as a patch reader. Keep
	// their memory and CPU overhead independent of the detector's CPU count.
	return min(Automatic(), 4)
}

func AutomaticFiles() int {
	processorJobs := Automatic()
	return max(processorJobs, min(processorJobs*4, 40))
}

func AutomaticObjects() int {
	return Automatic() * 2
}

const maxProviderTargetJobs = 4

func AutomaticProvider() int {
	return min(Automatic(), maxProviderTargetJobs)
}

func ProviderTargets(jobs int, singleTarget bool) int {
	if singleTarget {
		return 1
	}
	return min(jobs, maxProviderTargetJobs)
}

// Budget bounds leaf source work across nested sources. Provider target
// goroutines do not hold a slot while waiting for their Git or object work, so
// nested scans can share this budget without deadlocking.
type Budget struct {
	limit int
	slots chan struct{}
}

func NewBudget(jobs int) *Budget {
	jobs = max(jobs, 1)
	return &Budget{
		limit: jobs,
		slots: make(chan struct{}, jobs),
	}
}

func WithinBudget(configured, fallback int, existing *Budget) int {
	jobs := WorkerCount(configured, fallback)
	if existing != nil {
		jobs = min(jobs, existing.limit)
	}
	return jobs
}

func EnsureBudget(configured, fallback int, existing *Budget) (int, *Budget) {
	jobs := WithinBudget(configured, fallback, existing)
	if existing != nil {
		return jobs, existing
	}
	return jobs, NewBudget(jobs)
}

func (b *Budget) Run(ctx context.Context, fn func() error) error {
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

// WithBudget carries the shared leaf-work limit into a nested source.
// Providers do not acquire a slot while waiting for their nested Git scan.
func WithBudget(ctx context.Context, budget *Budget) context.Context {
	if budget == nil {
		return ctx
	}
	return context.WithValue(ctx, budgetKey{}, budget)
}

type budgetKey struct{}

func FromContext(ctx context.Context) *Budget {
	budget, _ := ctx.Value(budgetKey{}).(*Budget)
	return budget
}
