package rules

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
)

type fastmailFixtureTransport func(*http.Request) (*http.Response, error)

func (transport fastmailFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestFastmailAPITokenValidation(t *testing.T) {
	const secret = "fmu1-1a2b3c4d-9f8e7d6c5b4a39281706f5e4d3c2b1a0-0-0123456789abcdef0123456789abcdef"

	tests := []struct {
		name         string
		jmapStatus   int
		mcpStatus    int
		wantStatus   report.ValidationStatus
		wantRequests []string
	}{
		{"jmap token", http.StatusOK, 0, report.ValidationStatusValid, []string{"GET /jmap/session"}},
		{"mcp token", http.StatusUnauthorized, http.StatusOK, report.ValidationStatusValid, []string{"GET /jmap/session", "POST /mcp"}},
		{"rejected by both", http.StatusUnauthorized, http.StatusUnauthorized, report.ValidationStatusInvalid, []string{"GET /jmap/session", "POST /mcp"}},
		{"forbidden by both", http.StatusForbidden, http.StatusForbidden, report.ValidationStatusInvalid, []string{"GET /jmap/session", "POST /mcp"}},
		{"jmap server error", http.StatusInternalServerError, 0, report.ValidationStatusUnknown, []string{"GET /jmap/session"}},
		{"mcp server error", http.StatusUnauthorized, http.StatusInternalServerError, report.ValidationStatusUnknown, []string{"GET /jmap/session", "POST /mcp"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests []string
			runtime, err := exprruntime.New(&http.Client{Transport: fastmailFixtureTransport(func(request *http.Request) (*http.Response, error) {
				requests = append(requests, request.Method+" "+request.URL.Path)
				assert.Equal(t, "api.fastmail.com", request.URL.Host)
				assert.Equal(t, "Bearer "+secret, request.Header.Get("Authorization"))
				status := test.jmapStatus
				if request.URL.Path == "/mcp" {
					status = test.mcpStatus
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
			})})
			require.NoError(t, err)

			program, err := runtime.CompileValidation(FastmailAPIToken().ValidateExpr)
			require.NoError(t, err)
			value, err := runtime.EvalValidationWithComponents(
				t.Context(), program,
				map[string]string{"rule_id": "fastmail-api-token", "secret": secret},
				nil, nil, nil, exprruntime.EvalOptions{},
			)
			require.NoError(t, err)

			assert.Equal(t, test.wantStatus, provider.ParseResult(value.Value).Status)
			assert.Equal(t, test.wantRequests, requests)
		})
	}
}
