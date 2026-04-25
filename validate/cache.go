package validate

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/betterleaks/betterleaks/report"
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

// TODO maybe rename this to "components" and collapse secret into it too
func CacheKey(ruleID, secret string, auxiliary map[string]string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(secret))
	if len(auxiliary) > 0 {
		h.Write([]byte{0})
		keys := make([]string, 0, len(auxiliary))
		for k := range auxiliary {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte{0})
			h.Write([]byte(auxiliary[k]))
			h.Write([]byte{0})
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
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
		if result.Status != report.ValidationStatusError {
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
