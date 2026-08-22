package validate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/singleflight"
)

// Cache prevents duplicate HTTP requests for the same rule+secret combination.
// It uses singleflight to coalesce concurrent requests for the same key so that
// only one goroutine performs the actual evaluation.
type Cache struct {
	mu    sync.RWMutex
	store map[string]*Result

	hits   atomic.Uint64
	misses atomic.Uint64

	// sflight ensures concurrent lookups for the same key share a single eval.
	sflight singleflight.Group
}

func NewCache() *Cache {
	return &Cache{store: make(map[string]*Result)}
}

// CacheKey identifies a validation input. Captures and components occupy
// separate namespaces so identical user-defined keys cannot collide.
func CacheKey(ruleID, secret string, captures map[string]string, components map[string]cacheComponent) string {
	encoded, err := json.Marshal(struct {
		RuleID     string                    `json:"rule_id"`
		Secret     string                    `json:"secret"`
		Captures   map[string]string         `json:"captures,omitempty"`
		Components map[string]cacheComponent `json:"components,omitempty"`
	}{
		RuleID:     ruleID,
		Secret:     secret,
		Captures:   captures,
		Components: components,
	})
	if err != nil {
		panic(fmt.Sprintf("encode validation cache key: %v", err))
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

type cacheComponent struct {
	Secret string `json:"secret"`
	// Captures contains named regex capture groups only.
	Captures map[string]string `json:"captures,omitempty"`
}

// GetOrDo looks up key in the cache. On a hit it returns the cached result.
// On a miss it calls fn exactly once (even if many goroutines race on the
// same key) and caches non-error results before returning.
func (c *Cache) GetOrDo(key string, fn func() (*Result, error)) (*Result, error) {
	// Fast path: check the cache under a read lock.
	c.mu.RLock()
	r, ok := c.store[key]
	c.mu.RUnlock()
	if ok {
		c.hits.Add(1)
		return r, nil
	}

	// Slow path: coalesce concurrent callers via singleflight.
	v, err, _ := c.sflight.Do(key, func() (any, error) {
		c.misses.Add(1)
		result, fnErr := fn()
		if fnErr != nil {
			return nil, fnErr
		}

		// Cache non-error validation results.
		if result.Status != "error" {
			c.mu.Lock()
			c.store[key] = result
			c.mu.Unlock()
		}

		return result, nil
	})
	if err != nil {
		return nil, err
	}

	// cast to validation Result and return
	return v.(*Result), nil
}

// Hits returns the total number of cache hits.
func (c *Cache) Hits() uint64 { return c.hits.Load() }

// Misses returns the total number of cache misses.
func (c *Cache) Misses() uint64 { return c.misses.Load() }
