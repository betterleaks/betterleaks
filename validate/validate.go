package validate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
)

// Validator fires HTTP requests described in [rules.validate] blocks
// and annotates findings with a ValidationStatus.
type Validator struct {
	Config         config.Config
	HTTPClient     *http.Client
	Cache          *ResponseCache
	RequestTimeout time.Duration
	FullResponse   bool
	ExtractEmpty   bool
	Templates      *TemplateEngine

	// inflight deduplicates concurrent HTTP requests for the same cache key.
	inflight singleflight.Group

	// Attempted counts the total number of findings where validation was attempted.
	Attempted atomic.Int64

	// CacheHits counts how many validation lookups were served from cache.
	CacheHits atomic.Int64

	// HTTPRequests counts actual outbound HTTP requests (cache misses after singleflight).
	HTTPRequests atomic.Int64
}

// NewValidator creates a Validator with sensible defaults.
func NewValidator(cfg config.Config) *Validator {
	return &Validator{
		Config:         cfg,
		HTTPClient:     &http.Client{},
		Cache:          NewResponseCache(),
		RequestTimeout: 10 * time.Second,
		Templates:      NewTemplateEngine(),
	}
}

// ValidateFinding annotates a single finding in-place with a ValidationStatus.
// Returns true if the finding's rule had a validate block (i.e. validation was attempted).
// Safe for concurrent use — singleflight coalesces identical in-flight requests
// and the response cache provides cross-call deduplication.
func (v *Validator) ValidateFinding(ctx context.Context, f *report.Finding) bool {
	rule, ok := v.Config.Rules[f.RuleID]
	if !ok || rule.Validation == nil {
		return false
	}

	secrets := buildSecrets(f)

	allIDs := collectTemplateIDs(rule.Validation)
	if missing := missingIDs(allIDs, secrets); len(missing) > 0 {
		logging.Debug().
			Str("rule", f.RuleID).
			Strs("missing", missing).
			Msg("validation skipped: missing placeholders")
		return false
	}

	v.Attempted.Add(1)

	// Build one cartesian product across all placeholder IDs found in URL,
	// body, and headers. Each combo map is used to render every field, so
	// placeholders that appear in multiple fields always get consistent values.
	combos := Combos(allIDs, secrets)

	var lastResult string
	var lastMeta map[string]string
	var lastNote string
	var lastBody []byte

	for _, combo := range combos {
		renderedURL, err := v.Templates.Render(rule.Validation.URL, combo)
		if err != nil {
			f.ValidationStatus = report.ValidationError
			f.ValidationNote = fmt.Sprintf("template render (url): %s", err)
			return true
		}
		renderedBody, err := v.Templates.Render(rule.Validation.Body, combo)
		if err != nil {
			f.ValidationStatus = report.ValidationError
			f.ValidationNote = fmt.Sprintf("template render (body): %s", err)
			return true
		}
		renderedHeaders, err := v.Templates.RenderMap(rule.Validation.Headers, combo)
		if err != nil {
			f.ValidationStatus = report.ValidationError
			f.ValidationNote = fmt.Sprintf("template render (headers): %s", err)
			return true
		}

		cacheKey := v.Cache.Key(rule.Validation.Method, renderedURL, renderedHeaders, renderedBody)

		resp, err := v.getOrFetch(ctx, cacheKey, rule.Validation.Method, renderedURL, renderedHeaders, renderedBody)
		if err != nil {
			f.ValidationStatus = report.ValidationError
			f.ValidationNote = err.Error()
			return true
		}

		if resp.Err != nil {
			f.ValidationStatus = report.ValidationError
			f.ValidationNote = resp.Err.Error()
			return true
		}

		respHeaders := resp.Headers
		if respHeaders == nil {
			respHeaders = http.Header{}
		}
		result, meta, reason := rule.Validation.EvalMatch(resp.StatusCode, resp.Body, respHeaders, v.ExtractEmpty)
		lastResult = result
		lastMeta = meta
		lastNote = reason
		lastBody = resp.Body
		if result == "confirmed" {
			break
		}
	}

	switch lastResult {
	case "confirmed":
		f.ValidationStatus = report.ValidationConfirmed
		logging.Debug().
			Str("rule", f.RuleID).
			Str("file", f.File).
			Msg("secret confirmed live")
	case "invalid":
		f.ValidationStatus = report.ValidationInvalid
	case "revoked":
		f.ValidationStatus = report.ValidationRevoked
	case "unknown":
		f.ValidationStatus = report.ValidationUnknown
	default:
		f.ValidationStatus = report.ValidationError
	}
	f.ValidationNote = lastNote
	f.ValidationMeta = lastMeta
	if v.FullResponse {
		f.ValidationResponse = string(lastBody)
	}
	return true
}

// Validate annotates each finding with a ValidationStatus.
// Findings whose rule has no validate block are returned unchanged.
func (v *Validator) Validate(ctx context.Context, findings []report.Finding) []report.Finding {
	for i := range findings {
		v.ValidateFinding(ctx, &findings[i])
	}
	return findings
}

func buildSecrets(f *report.Finding) map[string][]string {
	secrets := make(map[string][]string)
	// Implicit variable — always available as {{ secret }}
	secrets["secret"] = []string{f.Secret}

	// Named captures become template variables
	for name, val := range f.CaptureGroups {
		secrets[name] = []string{val}
	}

	for _, rf := range f.RequiredFindings() {
		secrets[rf.RuleID] = appendUnique(secrets[rf.RuleID], rf.Secret)
		for name, val := range rf.CaptureGroups {
			key := rf.RuleID + "." + name
			secrets[key] = []string{val}
		}
	}
	return secrets
}

// getOrFetch checks the cache, and on miss uses singleflight to ensure only one
// in-flight HTTP request per unique cache key. Concurrent callers with the same
// key block until the first request completes, then share the result.
func (v *Validator) getOrFetch(ctx context.Context, cacheKey, method, url string, headers map[string]string, body string) (*CachedResponse, error) {
	if resp, ok := v.Cache.Get(cacheKey); ok {
		v.CacheHits.Add(1)
		logging.Debug().
			Str("request", KeyDebug(method, url, headers, body)).
			Msg("cache hit")
		return resp, nil
	}

	val, err, _ := v.inflight.Do(cacheKey, func() (any, error) {
		resp := v.doRequest(ctx, method, url, headers, body)
		// Only cache successful responses. Transient failures (DNS, TLS,
		// connection refused) should not poison the key for the entire run.
		if resp.Err == nil {
			v.Cache.Set(cacheKey, resp)
		}
		return resp, nil
	})
	if err != nil {
		return nil, err
	}
	return val.(*CachedResponse), nil
}

func (v *Validator) doRequest(ctx context.Context, method, url string, headers map[string]string, body string) *CachedResponse {
	v.HTTPRequests.Add(1)
	reqCtx, cancel := context.WithTimeout(ctx, v.RequestTimeout)
	defer cancel()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, url, bodyReader)
	if err != nil {
		return &CachedResponse{Err: err}
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}

	logging.Debug().
		Str("method", method).
		Str("url", url).
		Msg("validation request")

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return &CachedResponse{Err: err}
	}
	defer resp.Body.Close()

	// Cap response body to 10 MB to prevent OOM from oversized responses.
	const maxResponseBody = 10 << 20
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return &CachedResponse{Err: err}
	}

	return &CachedResponse{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}
}

func collectTemplateIDs(v *config.Validation) []string {
	var all []string
	all = append(all, PlaceholderIDs(v.URL)...)
	all = append(all, PlaceholderIDs(v.Body)...)
	for _, val := range v.Headers {
		all = append(all, PlaceholderIDs(val)...)
	}
	seen := make(map[string]struct{})
	var unique []string
	for _, id := range all {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			unique = append(unique, id)
		}
	}
	return unique
}

func missingIDs(needed []string, secrets map[string][]string) []string {
	var missing []string
	for _, id := range needed {
		if vals, ok := secrets[id]; !ok || len(vals) == 0 {
			missing = append(missing, id)
		}
	}
	return missing
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
