// Package cache provides scan-scoped memoization for provider evaluations.
package cache

import (
	"sync"
	"sync/atomic"

	"golang.org/x/sync/singleflight"
)

// Cache memoizes successful computations by key and coalesces concurrent
// misses. It is intentionally unbounded; callers should scope it to one scan.
type Cache[V any] struct {
	mu          sync.RWMutex
	store       map[string]V
	shouldStore func(V) bool
	hits        atomic.Uint64
	misses      atomic.Uint64
	group       singleflight.Group
}

// New returns a cache that stores every successful computation.
func New[V any]() *Cache[V] {
	return &Cache[V]{store: make(map[string]V)}
}

// NewWithStorePolicy returns a cache that stores successful computations only
// when shouldStore returns true. Errors are never stored.
func NewWithStorePolicy[V any](shouldStore func(V) bool) *Cache[V] {
	cache := New[V]()
	cache.shouldStore = shouldStore
	return cache
}

// GetOrDo returns a cached value or computes it once for concurrent callers.
func (c *Cache[V]) GetOrDo(key string, fn func() (V, error)) (V, error) {
	if value, ok := c.get(key); ok {
		c.hits.Add(1)
		return value, nil
	}

	value, err, _ := c.group.Do(key, func() (any, error) {
		// A prior singleflight call can finish between the fast-path lookup and
		// this call. Check again so that narrow race does not recompute the value.
		if value, ok := c.get(key); ok {
			c.hits.Add(1)
			return value, nil
		}

		c.misses.Add(1)
		value, err := fn()
		if err != nil {
			return nil, err
		}
		if c.shouldStore == nil || c.shouldStore(value) {
			c.mu.Lock()
			c.store[key] = value
			c.mu.Unlock()
		}
		return value, nil
	})
	if err != nil {
		var zero V
		return zero, err
	}
	return value.(V), nil
}

func (c *Cache[V]) get(key string) (V, bool) {
	c.mu.RLock()
	value, ok := c.store[key]
	c.mu.RUnlock()
	return value, ok
}

// Hits returns the number of lookups served from stored values.
func (c *Cache[V]) Hits() uint64 { return c.hits.Load() }

// Misses returns the number of computations performed.
func (c *Cache[V]) Misses() uint64 { return c.misses.Load() }
