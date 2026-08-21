package sources

import (
	"context"
)

// defaultSourceWorkers preserves the historical file-source concurrency limit.
const defaultSourceWorkers = 40

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment. Ownership of a non-nil fragment transfers to the callback. The
// callback may retain it after returning and must eventually call Release
// exactly once. The fragment is invalid after Release.
type FragmentsFunc func(fragment *Fragment, err error) error

// SkipFunc decides whether to skip a fragment based on its attributes.
// Returns true to skip (discard), false to keep.
// Used by sources as a callback to decouple path/commit filtering from config.
type SkipFunc func(attrs map[string]string) bool

// PathSkipFunc is the allocation-free path-only form used while walking a
// filesystem. Sources with richer attributes continue to use SkipFunc.
type PathSkipFunc func(path string) bool

// Source is a thing that can yield fragments
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source
	Fragments(ctx context.Context, yield FragmentsFunc) error
}

type sourceWorkersContextKey struct{}

type sourceWorkersConfig struct {
	configured int
}

// WithSourceWorkers returns a context carrying the source worker override used
// by sources that provide their own fixed worker pool. A non-positive value
// selects each source's default.
func WithSourceWorkers(ctx context.Context, workers int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if workers < 0 {
		workers = 0
	}
	return context.WithValue(ctx, sourceWorkersContextKey{}, &sourceWorkersConfig{
		configured: workers,
	})
}

func ensureSourceWorkers(ctx context.Context) context.Context {
	if sourceWorkersFromContext(ctx) != nil {
		return ctx
	}
	return WithSourceWorkers(ctx, 0)
}

func sourceWorkersFromContext(ctx context.Context) *sourceWorkersConfig {
	if ctx == nil {
		return nil
	}
	workers, _ := ctx.Value(sourceWorkersContextKey{}).(*sourceWorkersConfig)
	return workers
}

func sourceWorkerCount(ctx context.Context, fallback int) int {
	workers := sourceWorkersFromContext(ctx)
	if workers == nil {
		return fallback
	}
	return resolveSourceWorkerCount(workers.configured, fallback)
}

func sourceWorkerOverride(ctx context.Context) int {
	workers := sourceWorkersFromContext(ctx)
	if workers == nil {
		return 0
	}
	return workers.configured
}

func resolveSourceWorkerCount(configured, fallback int) int {
	if configured > 0 {
		return configured
	}
	return fallback
}
