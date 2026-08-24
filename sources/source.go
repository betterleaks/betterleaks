package sources

import (
	"context"
	"errors"

	"golang.org/x/sync/errgroup"
)

// defaultSourceWorkers preserves the historical file and Git source limit.
const defaultSourceWorkers = 40

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
	// fragments in the source
	Fragments(ctx context.Context, yield FragmentsFunc) error
}

type sourceWorkersContextKey struct{}

type sourceWorkerLimiter struct {
	tokens chan struct{}
}

type sourceWorkersConfig struct {
	configured int
	limiter    *sourceWorkerLimiter
}

// WithSourceWorkers returns a context carrying one shared source-task limit.
// Nested Files and Git sources inherit the same limiter, so provider and
// parallel Git fan-out cannot multiply file/diff task concurrency.
func WithSourceWorkers(ctx context.Context, workers int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if workers < 0 {
		workers = 0
	}
	return context.WithValue(ctx, sourceWorkersContextKey{}, &sourceWorkersConfig{
		configured: workers,
		limiter: &sourceWorkerLimiter{
			tokens: make(chan struct{}, resolveSourceWorkerCount(workers, defaultSourceWorkers)),
		},
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

func (l *sourceWorkerLimiter) acquire(ctx context.Context) error {
	select {
	case l.tokens <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *sourceWorkerLimiter) release() {
	<-l.tokens
}

// sourceTaskGroup owns the goroutines started by one source while sharing its
// limiter with every nested source in the same scan.
type sourceTaskGroup struct {
	ctx     context.Context
	group   errgroup.Group
	limiter *sourceWorkerLimiter
}

func newSourceTaskGroup(ctx context.Context) *sourceTaskGroup {
	ctx = ensureSourceWorkers(ctx)
	return &sourceTaskGroup{
		ctx:     ctx,
		group:   errgroup.Group{},
		limiter: sourceWorkersFromContext(ctx).limiter,
	}
}

func (g *sourceTaskGroup) Go(fn func(context.Context) error) error {
	if err := g.limiter.acquire(g.ctx); err != nil {
		return err
	}
	if err := g.ctx.Err(); err != nil {
		g.limiter.release()
		return err
	}
	g.group.Go(func() error {
		defer g.limiter.release()
		return fn(g.ctx)
	})
	return nil
}

func (g *sourceTaskGroup) Wait(producerErr error) error {
	taskErr := g.group.Wait()
	if taskErr == nil {
		return producerErr
	}
	if producerErr == nil || errors.Is(producerErr, context.Canceled) {
		return taskErr
	}
	return errors.Join(producerErr, taskErr)
}
