package validate

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/report"
)

// CachedResult stores the final validation outcome for a rule+secret combination.
type CachedResult struct {
	Status report.ValidationStatus
	Meta   map[string]string
	Note   string
	Body   []byte // only populated when FullResponse is enabled
	Err    error
}

// ResultCache is a concurrency-safe, in-memory, per-run cache keyed by
// rule ID + the full secrets map (including required-finding secrets).
type ResultCache struct {
	mu    sync.RWMutex
	store map[string]*CachedResult
}

// NewResultCache returns an initialized ResultCache.
func NewResultCache() *ResultCache {
	return &ResultCache{store: make(map[string]*CachedResult)}
}

// Key computes a deterministic cache key from the rule ID and the full
// secrets map produced by buildSecrets (own secret, capture groups,
// and all required-finding secrets/captures).
func (c *ResultCache) Key(ruleID string, secrets map[string][]string) string {
	h := sha256.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0}) // separator

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		vals := secrets[k]
		sorted := make([]string, len(vals))
		copy(sorted, vals)
		sort.Strings(sorted)
		for _, v := range sorted {
			h.Write([]byte(v))
			h.Write([]byte{0})
		}
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// Get retrieves a cached result. Returns nil, false on miss.
func (c *ResultCache) Get(key string) (*CachedResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.store[key]
	return r, ok
}

// Set stores a result in the cache.
func (c *ResultCache) Set(key string, r *CachedResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = r
}

// Size returns the number of cached entries.
func (c *ResultCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

// KeyDebug returns a human-readable summary of what goes into the cache key
// (for debug logging only, never for actual keying).
func KeyDebug(ruleID string, secrets map[string][]string) string {
	var sb strings.Builder
	sb.WriteString(ruleID)
	sb.WriteByte(' ')
	sb.WriteString(fmt.Sprintf("[%d placeholders]", len(secrets)))
	return sb.String()
}
