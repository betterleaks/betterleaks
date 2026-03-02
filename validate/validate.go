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
	Config          config.Config
	HTTPClient      *http.Client
	Cache           *ResultCache
	RequestTimeout  time.Duration
	FullResponse    bool
	ExtractEmpty    bool
	IncludeRequests bool
	Templates       *TemplateEngine

	// inflight deduplicates concurrent validations for the same rule+secret.
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
		Cache:          NewResultCache(),
		RequestTimeout: 10 * time.Second,
		Templates:      NewTemplateEngine(),
	}
}

// ValidateFinding annotates a single finding in-place with a ValidationStatus.
// Returns true if the finding's rule had a validate block (i.e. validation was attempted).
// Safe for concurrent use — singleflight coalesces identical in-flight validations
// and the result cache provides cross-call deduplication.
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

	cacheKey := v.Cache.Key(f.RuleID, secrets)

	// Fast path: result already cached from a previous finding with the same rule+secret.
	if cached, ok := v.Cache.Get(cacheKey); ok {
		v.CacheHits.Add(1)
		logging.Debug().
			Str("rule", f.RuleID).
			Str("cache_key", KeyDebug(f.RuleID, secrets)).
			Msg("validation cache hit")
		applyCachedResult(f, cached, v.FullResponse)
		return true
	}

	// Singleflight at the rule+secret level: concurrent goroutines validating
	// the same secret against the same rule share a single validation pass.
	val, err, _ := v.inflight.Do(cacheKey, func() (any, error) {
		result := v.runValidation(ctx, rule, secrets)
		if result.Err == nil {
			v.Cache.Set(cacheKey, result)
		}
		return result, nil
	})
	if err != nil {
		f.ValidationStatus = report.ValidationError
		f.ValidationNote = err.Error()
		return true
	}

	applyCachedResult(f, val.(*CachedResult), v.FullResponse)
	return true
}

// runValidation executes the full validation flow: template rendering,
// combo iteration, HTTP requests, and match evaluation. Returns a
// CachedResult representing the final outcome.
func (v *Validator) runValidation(ctx context.Context, rule config.Rule, secrets map[string][]string) *CachedResult {
	allIDs := collectTemplateIDs(rule.Validation)
	combos := Combos(allIDs, secrets)

	var lastResult string
	var lastMeta map[string]string
	var lastNote string
	var lastBody []byte

	for _, combo := range combos {
		renderedURL, err := v.Templates.Render(rule.Validation.URL, combo)
		if err != nil {
			return &CachedResult{
				Status: report.ValidationError,
				Note:   fmt.Sprintf("template render (url): %s", err),
				Err:    err,
			}
		}
		renderedBody, err := v.Templates.Render(rule.Validation.Body, combo)
		if err != nil {
			return &CachedResult{
				Status: report.ValidationError,
				Note:   fmt.Sprintf("template render (body): %s", err),
				Err:    err,
			}
		}
		renderedHeaders, err := v.Templates.RenderMap(rule.Validation.Headers, combo)
		if err != nil {
			return &CachedResult{
				Status: report.ValidationError,
				Note:   fmt.Sprintf("template render (headers): %s", err),
				Err:    err,
			}
		}

		resp, err := v.doRequest(ctx, rule.Validation.Method, renderedURL, renderedHeaders, renderedBody)
		if err != nil {
			return &CachedResult{
				Status: report.ValidationError,
				Note:   err.Error(),
				Err:    err,
			}
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
		if result == "valid" {
			break
		}
	}

	cached := &CachedResult{
		Meta: lastMeta,
		Note: lastNote,
	}
	if v.FullResponse {
		cached.Body = lastBody
	}

	switch lastResult {
	case "valid":
		cached.Status = report.ValidationValid
	case "invalid":
		cached.Status = report.ValidationInvalid
	case "revoked":
		cached.Status = report.ValidationRevoked
	case "unknown":
		cached.Status = report.ValidationUnknown
	default:
		cached.Status = report.ValidationError
	}

	return cached
}

// applyCachedResult assigns a CachedResult's fields to a Finding.
func applyCachedResult(f *report.Finding, r *CachedResult, fullResponse bool) {
	f.ValidationStatus = r.Status
	f.ValidationNote = r.Note
	f.ValidationMeta = r.Meta
	if fullResponse && len(r.Body) > 0 {
		f.ValidationResponse = string(r.Body)
	}
	if r.Status == report.ValidationValid {
		logging.Debug().
			Str("rule", f.RuleID).
			Str("file", f.File).
			Msg("secret validated live")
	}
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
	secrets["secret"] = []string{f.Secret}

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

// httpResponse is an internal type for passing raw HTTP response data
// from doRequest to runValidation.
type httpResponse struct {
	StatusCode int
	Body       []byte
	Headers    http.Header
}

func (v *Validator) doRequest(ctx context.Context, method, url string, headers map[string]string, body string) (*httpResponse, error) {
	v.HTTPRequests.Add(1)
	reqCtx, cancel := context.WithTimeout(ctx, v.RequestTimeout)
	defer cancel()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}

	if v.IncludeRequests {
		evt := logging.Info().
			Str("method", method).
			Str("url", url)
		for k, val := range headers {
			evt = evt.Str("req_header_"+k, val)
		}
		if body != "" {
			evt = evt.Str("body", body)
		}
		evt.Msg("validation request →")
	} else {
		logging.Debug().
			Str("method", method).
			Str("url", url).
			Msg("validation request")
	}

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		if v.IncludeRequests {
			logging.Info().Err(err).
				Str("method", method).
				Str("url", url).
				Msg("validation request failed")
		}
		return nil, err
	}
	defer func() { 
	  _, _ = io.ReadAll(io.Discard, res.Body)
	  _ = resp.Body.Close()
    }()

	const maxResponseBody = 10 << 20
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, err
	}

	if v.IncludeRequests {
		evt := logging.Info().
			Str("method", method).
			Str("url", url).
			Int("status", resp.StatusCode)
		for k, vals := range resp.Header {
			evt = evt.Strs("resp_header_"+k, vals)
		}
		if len(respBody) <= 4096 {
			evt = evt.Str("resp_body", string(respBody))
		} else {
			evt = evt.Str("resp_body", string(respBody[:4096])+"… (truncated)")
		}
		evt.Msg("validation response ←")
	}

	return &httpResponse{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Headers:    resp.Header,
	}, nil
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
