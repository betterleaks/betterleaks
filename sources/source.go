package sources

import "context"

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

const maxProviderTargetWorkers = 4

// providerWorkerAllocation divides an explicit source-worker budget between
// top-level provider targets and the Git or file work within each target.
// WorkersPerTarget is zero when the source should retain its historical
// defaults.
type providerWorkerAllocation struct {
	TargetWorkers    int
	WorkersPerTarget int
}

func allocateProviderWorkers(configured, defaultTargetWorkers int, singleTarget bool) providerWorkerAllocation {
	if configured <= 0 {
		if singleTarget {
			defaultTargetWorkers = 1
		}
		return providerWorkerAllocation{TargetWorkers: defaultTargetWorkers}
	}
	if singleTarget {
		return providerWorkerAllocation{
			TargetWorkers:    1,
			WorkersPerTarget: configured,
		}
	}

	targetWorkers := min(max(configured/4, 1), maxProviderTargetWorkers)
	return providerWorkerAllocation{
		TargetWorkers:    targetWorkers,
		WorkersPerTarget: max((configured-targetWorkers)/targetWorkers, 1),
	}
}
