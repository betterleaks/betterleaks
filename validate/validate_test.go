package validate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
)

func TestValidator_Validate_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"access_token": "live"}`))
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "POST",
					URL:    srv.URL + "/token",
					Body:   "secret={{ secret }}",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Words: []string{"access_token"}, Result: "confirmed"},
					},
				},
			},
		},
	}

	findings := []report.Finding{
		{
			RuleID: "test.rule",
			Secret: "my-secret-value",
		},
	}

	v := NewValidator(cfg)
	result := v.Validate(context.Background(), findings)
	require.Len(t, result, 1)
	assert.Equal(t, report.ValidationConfirmed, result[0].ValidationStatus)
}

func TestValidator_Validate_Invalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error": "bad_credentials"}`))
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
					URL:    srv.URL + "/check",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
						{StatusCodes: []int{401}, Result: "invalid"},
					},
				},
			},
		},
	}

	findings := []report.Finding{
		{
			RuleID: "test.rule",
			Secret: "bad-secret",
		},
	}

	v := NewValidator(cfg)
	result := v.Validate(context.Background(), findings)
	require.Len(t, result, 1)
	assert.Equal(t, report.ValidationInvalid, result[0].ValidationStatus)
}

func TestValidator_Validate_NoValidationBlock(t *testing.T) {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"plain.rule": {RuleID: "plain.rule"},
		},
	}

	findings := []report.Finding{
		{RuleID: "plain.rule", Secret: "s"},
	}

	v := NewValidator(cfg)
	result := v.Validate(context.Background(), findings)
	require.Len(t, result, 1)
	// No validation block => status stays at zero value (empty string)
	assert.Empty(t, string(result[0].ValidationStatus))
}

func TestValidator_Validate_CacheHit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
				URL:    srv.URL + "/check?key={{ secret }}",
				Match: []config.MatchClause{
					{StatusCodes: []int{200}, Result: "confirmed"},
				},
			},
		},
	},
}

	findings := []report.Finding{
		{RuleID: "test.rule", Secret: "same-secret"},
		{RuleID: "test.rule", Secret: "same-secret"},
	}

	v := NewValidator(cfg)
	result := v.Validate(context.Background(), findings)
	require.Len(t, result, 2)
	assert.Equal(t, report.ValidationConfirmed, result[0].ValidationStatus)
	assert.Equal(t, report.ValidationConfirmed, result[1].ValidationStatus)
	assert.Equal(t, 1, calls, "should have only made one HTTP request due to cache")
}

func TestValidator_Validate_CartesianProduct(t *testing.T) {
	var receivedBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		receivedBodies = append(receivedBodies, string(body))
		w.WriteHeader(403)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"composite.rule": {
				RuleID: "composite.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "POST",
					URL:    srv.URL,
					Body:   "id={{ dep.id }}&secret={{ secret }}",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
						{Result: "invalid"},
					},
				},
			},
		},
	}

	f := report.Finding{
		RuleID: "composite.rule",
		Secret: "sec1",
	}
	f.AddRequiredFindings([]*report.RequiredFinding{
		{RuleID: "dep.id", Secret: "id1"},
		{RuleID: "dep.id", Secret: "id2"},
	})

	v := NewValidator(cfg)
	result := v.Validate(context.Background(), []report.Finding{f})
	require.Len(t, result, 1)
	assert.Equal(t, report.ValidationInvalid, result[0].ValidationStatus)
	assert.Equal(t, 2, len(receivedBodies), "should produce 2 combos: 2 IDs × 1 secret")
}

func TestValidator_Validate_SharedPlaceholder_ConsistentCombo(t *testing.T) {
	type request struct {
		url  string
		body string
	}
	var mu sync.Mutex
	var received []request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		mu.Lock()
		received = append(received, request{url: r.URL.String(), body: string(b)})
		mu.Unlock()
		w.WriteHeader(403)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "POST",
				URL:    srv.URL + "/check?id={{ dep.id }}",
				Body:   "id={{ dep.id }}&secret={{ secret }}",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
						{Result: "invalid"},
					},
				},
			},
		},
	}

	f := report.Finding{RuleID: "test.rule", Secret: "sec1"}
	f.AddRequiredFindings([]*report.RequiredFinding{
		{RuleID: "dep.id", Secret: "id1"},
		{RuleID: "dep.id", Secret: "id2"},
	})

	v := NewValidator(cfg)
	v.Validate(context.Background(), []report.Finding{f})

	require.Len(t, received, 2, "shared placeholder must not produce cross-product")

	for _, req := range received {
		if strings.Contains(req.url, "id=id1") {
			assert.Contains(t, req.body, "id=id1", "URL has id1 but body doesn't")
		} else if strings.Contains(req.url, "id=id2") {
			assert.Contains(t, req.body, "id=id2", "URL has id2 but body doesn't")
		} else {
			t.Errorf("unexpected URL: %s", req.url)
		}
	}
}

func TestValidator_Validate_HeadersIncludedInCombo(t *testing.T) {
	var receivedAuth []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = append(receivedAuth, r.Header.Get("Authorization"))
		w.WriteHeader(403)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:    config.ValidationTypeHTTP,
					Method:  "GET",
					URL:     srv.URL,
					Headers: map[string]string{"Authorization": "Bearer {{ secret }}"},
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
						{Result: "invalid"},
					},
				},
			},
		},
	}

	findings := []report.Finding{
		{RuleID: "test.rule", Secret: "tok1"},
		{RuleID: "test.rule", Secret: "tok2"},
	}

	v := NewValidator(cfg)
	v.Validate(context.Background(), findings)

	require.Len(t, receivedAuth, 2)
	assert.Contains(t, receivedAuth, "Bearer tok1")
	assert.Contains(t, receivedAuth, "Bearer tok2")
}

func TestValidator_Validate_NetworkError_IsValidationError(t *testing.T) {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
					URL:    "http://127.0.0.1:1/unreachable",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	findings := []report.Finding{
		{RuleID: "test.rule", Secret: "s"},
	}

	v := NewValidator(cfg)
	v.RequestTimeout = 1 * time.Second
	result := v.Validate(context.Background(), findings)
	require.Len(t, result, 1)
	assert.Equal(t, report.ValidationError, result[0].ValidationStatus,
		"network errors should be ValidationError, not ValidationInvalid")
	assert.NotEmpty(t, result[0].ValidationNote)
}

func TestValidator_Validate_NetworkError_NotCached(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
				URL:    srv.URL + "/check?key={{ secret }}",
				Match: []config.MatchClause{
					{StatusCodes: []int{200}, Result: "confirmed"},
				},
			},
		},
	},
}

	v := NewValidator(cfg)

	srv.Close()
	f1 := report.Finding{RuleID: "test.rule", Secret: "s"}
	v.ValidateFinding(context.Background(), &f1)
	assert.Equal(t, report.ValidationError, f1.ValidationStatus)

	assert.Equal(t, 0, v.Cache.Size(), "errored responses should not be cached")
}

func TestValidator_Validate_MissingPlaceholder_NotAttempted(t *testing.T) {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
					URL:    "http://localhost/check?id={{ missing.dep }}",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	findings := []report.Finding{
		{RuleID: "test.rule", Secret: "s"},
	}

	v := NewValidator(cfg)
	result := v.Validate(context.Background(), findings)
	require.Len(t, result, 1)
	// Missing placeholders => validation not attempted => status stays empty
	assert.Empty(t, string(result[0].ValidationStatus))
}

func TestValidator_Validate_RequestBodyRendered(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:    config.ValidationTypeHTTP,
					Method:  "POST",
					URL:     srv.URL,
					Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
					Body:    "token={{ secret }}",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	findings := []report.Finding{
		{RuleID: "test.rule", Secret: "abc123"},
	}

	v := NewValidator(cfg)
	v.Validate(context.Background(), findings)
	assert.Equal(t, "token=abc123", gotBody)
}

func TestValidateFinding_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
					URL:    srv.URL,
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	f := report.Finding{RuleID: "test.rule", Secret: "s"}
	v := NewValidator(cfg)

	attempted := v.ValidateFinding(context.Background(), &f)
	assert.True(t, attempted)
	assert.Equal(t, report.ValidationConfirmed, f.ValidationStatus)
}

func TestValidateFinding_NoBlock(t *testing.T) {
	cfg := config.Config{
		Rules: map[string]config.Rule{
			"plain": {RuleID: "plain"},
		},
	}

	f := report.Finding{RuleID: "plain", Secret: "s"}
	v := NewValidator(cfg)

	attempted := v.ValidateFinding(context.Background(), &f)
	assert.False(t, attempted)
	assert.Empty(t, string(f.ValidationStatus))
}

func TestValidateFinding_ConcurrentSafe(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
				URL:    srv.URL + "/check?key={{ secret }}",
				Match: []config.MatchClause{
					{StatusCodes: []int{200}, Result: "confirmed"},
				},
			},
		},
	},
}

	v := NewValidator(cfg)

	var wg sync.WaitGroup
	findings := make([]report.Finding, 20)
	for i := range findings {
		findings[i] = report.Finding{RuleID: "test.rule", Secret: "same-secret"}
	}

	for i := range findings {
		wg.Add(1)
		go func(f *report.Finding) {
			defer wg.Done()
			v.ValidateFinding(context.Background(), f)
		}(&findings[i])
	}
	wg.Wait()

	for _, f := range findings {
		assert.Equal(t, report.ValidationConfirmed, f.ValidationStatus)
	}
	assert.Equal(t, int32(1), calls.Load(), "cache should collapse identical requests")
}

func TestValidateFinding_ConfirmedShortCircuitsCombos(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "POST",
					URL:    srv.URL,
				Body:   "id={{ dep.id }}&secret={{ secret }}",
				Match: []config.MatchClause{
					{StatusCodes: []int{200}, Words: []string{`"ok":true`}, Result: "confirmed"},
					{Result: "error"},
					},
				},
			},
		},
	}

	f := report.Finding{RuleID: "test.rule", Secret: "sec1"}
	f.AddRequiredFindings([]*report.RequiredFinding{
		{RuleID: "dep.id", Secret: "id1"},
		{RuleID: "dep.id", Secret: "id2"},
		{RuleID: "dep.id", Secret: "id3"},
	})

	v := NewValidator(cfg)
	v.ValidateFinding(context.Background(), &f)

	assert.Equal(t, report.ValidationConfirmed, f.ValidationStatus)
	assert.Equal(t, int32(1), calls.Load(),
		"should stop after first confirmed combo, not try all 3")
}

func TestValidateFinding_Revoked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":false,"error":"token_revoked"}`))
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "POST",
					URL:    srv.URL,
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Words: []string{`"ok":true`}, Result: "confirmed"},
						{StatusCodes: []int{200}, Words: []string{"token_revoked"}, Result: "revoked"},
						{StatusCodes: []int{200}, Words: []string{"invalid_auth"}, Result: "invalid"},
					},
				},
			},
		},
	}

	f := report.Finding{RuleID: "test.rule", Secret: "xoxb-old-token"}
	v := NewValidator(cfg)
	v.ValidateFinding(context.Background(), &f)
	assert.Equal(t, report.ValidationRevoked, f.ValidationStatus)
}

func TestValidateFinding_FullResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true,"user":"alice"}`))
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "GET",
					URL:    srv.URL,
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	f := report.Finding{RuleID: "test.rule", Secret: "s"}
	v := NewValidator(cfg)
	v.FullResponse = true
	v.ValidateFinding(context.Background(), &f)
	assert.Equal(t, report.ValidationConfirmed, f.ValidationStatus)
	assert.Equal(t, `{"ok":true,"user":"alice"}`, f.ValidationResponse)
}

func TestValidateFinding_ImplicitSecretVariable(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:    config.ValidationTypeHTTP,
					Method:  "GET",
					URL:     srv.URL,
					Headers: map[string]string{"Authorization": "token {{ secret }}"},
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	f := report.Finding{RuleID: "test.rule", Secret: "ghp_abc123"}
	v := NewValidator(cfg)
	v.ValidateFinding(context.Background(), &f)
	assert.Equal(t, report.ValidationConfirmed, f.ValidationStatus)
	assert.Equal(t, "token ghp_abc123", gotAuth)
}

func TestValidateFinding_NamedCaptureGroups(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cfg := config.Config{
		Rules: map[string]config.Rule{
			"test.rule": {
				RuleID: "test.rule",
				Validate: &config.Validation{
					Type:   config.ValidationTypeHTTP,
					Method: "POST",
					URL:    srv.URL,
					Body:   "id={{ key_id }}&secret={{ key_secret }}",
					Match: []config.MatchClause{
						{StatusCodes: []int{200}, Result: "confirmed"},
					},
				},
			},
		},
	}

	f := report.Finding{
		RuleID: "test.rule",
		Secret: "AKIAIOSFODNN7EXAMPLE",
		CaptureGroups: map[string]string{
			"key_id":     "AKIAIOSFODNN7EXAMPLE",
			"key_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}
	v := NewValidator(cfg)
	v.ValidateFinding(context.Background(), &f)
	assert.Equal(t, report.ValidationConfirmed, f.ValidationStatus)
	assert.Equal(t, "id=AKIAIOSFODNN7EXAMPLE&secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", gotBody)
}
