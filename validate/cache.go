package validate

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// CachedResponse stores the status code, body, and headers of an HTTP response.
type CachedResponse struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
	Err        error
}

// ResponseCache is a concurrency-safe, in-memory, per-run cache keyed by
// the full request signature (method + URL + sorted headers + body).
type ResponseCache struct {
	mu    sync.RWMutex
	store map[string]*CachedResponse
}

// NewResponseCache returns an initialized ResponseCache.
func NewResponseCache() *ResponseCache {
	return &ResponseCache{store: make(map[string]*CachedResponse)}
}

// Key computes a deterministic cache key from the request parameters.
func (c *ResponseCache) Key(method, url string, headers map[string]string, body string) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte(url))

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte(headers[k]))
	}

	h.Write([]byte(body))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Get retrieves a cached response. Returns nil, false on miss.
func (c *ResponseCache) Get(key string) (*CachedResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.store[key]
	return r, ok
}

// Set stores a response in the cache.
func (c *ResponseCache) Set(key string, r *CachedResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = r
}

// Size returns the number of cached entries.
func (c *ResponseCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

// KeyDebug returns a human-readable summary of what goes into the cache key
// (for debug logging only, never for actual keying).
func KeyDebug(method, url string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte(' ')
	sb.WriteString(url)
	if len(headers) > 0 {
		sb.WriteString(" [headers]")
	}
	if body != "" {
		if len(body) > 40 {
			sb.WriteString(" body=")
			sb.WriteString(body[:40])
			sb.WriteString("…")
		} else {
			sb.WriteString(" body=")
			sb.WriteString(body)
		}
	}
	return sb.String()
}
