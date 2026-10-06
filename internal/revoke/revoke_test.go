package revoke

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

func TestRequestBudgetAndNoResultCache(t *testing.T) {
	var requests, deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodDelete {
			deletes.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: "unused", RevokeExpr: fmt.Sprintf(`
let lookup = http.get(%q, {});
let deleted = http.delete(%q, {});
{"result": "revoked"}
`, server.URL, server.URL)}}}
	input := credential.Input{RuleID: "token", Secret: "primary-secret"}
	for _, limit := range []int{1, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			requests.Store(0)
			deletes.Store(0)
			for range 2 {
				result, err := Run(t.Context(), cfg, input, provider.RuntimeOptions{MaxRequestsPerTarget: limit})
				require.NoError(t, err)
				if limit == 1 {
					require.Equal(t, report.ValidationStatusUnknown, result.Analysis.Status)
					require.Contains(t, result.Analysis.StatusReason, "request limit")
				} else {
					require.Equal(t, report.ValidationStatusRevoked, result.Analysis.Status)
				}
			}
			require.EqualValues(t, 2*limit, requests.Load())
			require.EqualValues(t, 2*(limit-1), deletes.Load())
		})
	}
}

func TestRevocationCancellationAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes.Add(1)
				}
				if !timeout {
					cancel()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: "unused", RevokeExpr: fmt.Sprintf(`
let lookup = http.get(%q, {});
let deleted = http.delete(%q, {});
{"result": "revoked"}
`, server.URL, server.URL)}}}
			options := provider.RuntimeOptions{}
			if timeout {
				options.Timeout = 50 * time.Millisecond
			}
			result, err := Run(ctx, cfg, credential.Input{RuleID: "token", Secret: "primary-secret"}, options)
			if timeout {
				require.NoError(t, err)
				require.Equal(t, report.ValidationStatusUnknown, result.Analysis.Status)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Zero(t, deletes.Load())
		})
	}
	_, err := Run(nil, nil, credential.Input{}, provider.RuntimeOptions{})
	require.ErrorContains(t, err, "context must not be nil")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = Run(ctx, nil, credential.Input{}, provider.RuntimeOptions{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestRevocationChecksInputBeforeProviderRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "component", Regex: "unused"},
		{ID: "token", Regex: "unused", Components: []config.Component{{RuleID: "component"}}, RevokeExpr: fmt.Sprintf(`
let response = http.delete(%q, {"X-Tenant": finding.captures.tenant});
{"result": "revoked"}
`, server.URL)},
	}}
	for _, input := range []credential.Input{
		{RuleID: "token"},
		{RuleID: "token", Secret: "primary-secret"},
		{RuleID: "token", Secret: "primary-secret", Captures: map[string]string{"tenant": "tenant-value"}},
		{RuleID: "token", Secret: "primary-secret", Captures: map[string]string{"tenant": "tenant-value"}, Components: map[string]credential.Component{"wrong": {Secret: "component-secret"}}},
	} {
		_, err := Run(t.Context(), cfg, input, provider.RuntimeOptions{})
		require.Error(t, err)
	}
	require.Zero(t, requests.Load())
}

func TestRevocationEnvironmentAndRedaction(t *testing.T) {
	t.Setenv("REVOCATION_TEST_SCOPE", "test-scope")
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: "unused", RevokeExpr: `
env.get("REVOCATION_TEST_SCOPE") == "test-scope" ? {
  "result": "revoked", "metadata": {"echo": finding.secret}
} : {"result": "error"}
`}}}
	input := credential.Input{RuleID: "token", Secret: "primary-secret"}
	result, err := Run(t.Context(), cfg, input, provider.RuntimeOptions{})
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusError, result.Analysis.Status)
	result, err = Run(t.Context(), cfg, input, provider.RuntimeOptions{EnvVars: []string{"REVOCATION_TEST_SCOPE"}})
	require.NoError(t, err)
	require.Equal(t, report.ValidationStatusRevoked, result.Analysis.Status)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), input.Secret)
	require.Equal(t, "[redacted]", result.Analysis.StatusMetadata["echo"])
}

func TestRevocationResultContract(t *testing.T) {
	for _, test := range []struct {
		value any
		want  report.ValidationStatus
	}{
		{map[string]any{"result": "revoked"}, report.ValidationStatusRevoked},
		{map[string]any{"result": "unknown"}, report.ValidationStatusUnknown},
		{map[string]any{"result": "error"}, report.ValidationStatusError},
		{map[string]any{"result": "valid"}, report.ValidationStatusError},
		{map[string]any{"result": "accepted"}, report.ValidationStatusError},
		{map[string]any{"result": "revoked", "response": "raw-provider-response"}, report.ValidationStatusError},
		{map[string]any{"result": "revoked", "reason": 1}, report.ValidationStatusError},
		{map[string]any{"result": "revoked", "metadata": "raw-provider-response"}, report.ValidationStatusError},
		{true, report.ValidationStatusError},
		{nil, report.ValidationStatusError},
	} {
		result := parseResult(test.value)
		require.Equal(t, test.want, result.Status, "%v", test.value)
		require.Empty(t, result.StatusMetadata)
	}
}
