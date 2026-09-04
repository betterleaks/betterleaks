package rules

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/analyze"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	validatepkg "github.com/betterleaks/betterleaks/v2/internal/validate"
	"github.com/betterleaks/betterleaks/v2/report"
)

type cloudflareFixtureTransport func(*http.Request) (*http.Response, error)

func (transport cloudflareFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestCloudflareAPIKeyV2Formats(t *testing.T) {
	rule := CloudflareAPIKeyV2()
	require.Equal(t, []*config.Component{{RuleID: "cloudflare-account-id.1", Optional: true, Within: "5L"}}, rule.Components)

	tests := []struct {
		name  string
		token string
		match bool
	}{
		{name: "user token", token: "cfut_" + strings.Repeat("A1b2", 10) + "deadbeef", match: true},
		{name: "account token", token: "cfat_" + strings.Repeat("Z9y8", 10) + "cafebabe", match: true},
		{name: "short payload", token: "cfut_A1b2C3d4deadbeef"},
		{name: "uppercase checksum", token: "cfat_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0CAFEBABE"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches := rule.Regex.FindStringSubmatch("token = " + test.token)
			if !test.match {
				assert.Empty(t, matches)
				return
			}
			require.Len(t, matches, 2)
			assert.Equal(t, test.token, matches[1])
		})
	}
}

func TestCloudflareAPIKeyValidationRoutes(t *testing.T) {
	const accountID = "11111111111111111111111111111111"
	tests := []struct {
		name          string
		secret        string
		components    map[string]any
		wantPath      string
		wantStatus    report.ValidationStatus
		wantAccountID string
	}{
		{
			name:       "user token",
			secret:     "cfut_fixture",
			wantPath:   "/client/v4/user/tokens/verify",
			wantStatus: report.ValidationStatusValid,
		},
		{
			name:          "account ID",
			secret:        "cfat_fixture",
			components:    map[string]any{"cloudflare-account-id.1": map[string]any{"secret": accountID}},
			wantPath:      "/client/v4/accounts/" + accountID + "/tokens/verify",
			wantStatus:    report.ValidationStatusValid,
			wantAccountID: accountID,
		},
		{
			name:       "missing account context",
			secret:     "cfat_fixture",
			wantStatus: report.ValidationStatusNeedsValidation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			runtime, err := exprruntime.New(&http.Client{Transport: cloudflareFixtureTransport(func(request *http.Request) (*http.Response, error) {
				requests++
				assert.Equal(t, test.wantPath, request.URL.Path)
				assert.Equal(t, "Bearer "+test.secret, request.Header.Get("Authorization"))
				return cloudflareResponse(http.StatusOK, `{"result":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"active","not_before":"2026-09-05T00:00:00Z","expires_on":"2026-09-05T23:59:59Z"},"success":true}`), nil
			})})
			require.NoError(t, err)

			program, err := runtime.CompileValidation(cloudflareAPITokenValidateExpr)
			require.NoError(t, err)
			value, err := runtime.EvalValidationWithComponents(
				t.Context(), program,
				map[string]string{"rule_id": "cloudflare-api-key.2", "secret": test.secret},
				nil, test.components, nil, exprruntime.EvalOptions{},
			)
			require.NoError(t, err)
			result := validatepkg.ParseResult(value.Value)

			assert.Equal(t, test.wantStatus, result.Status)
			assert.Empty(t, result.Metadata)
			if test.wantStatus == report.ValidationStatusNeedsValidation {
				assert.Zero(t, requests)
				assert.Contains(t, result.Reason, "account ID")
				return
			}
			assert.Equal(t, 1, requests)
			wantTokenType := "user"
			if strings.HasPrefix(test.secret, "cfat_") {
				wantTokenType = "account"
			}
			assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result.Analysis["token_id"])
			assert.Equal(t, wantTokenType, result.Analysis["token_type"])
			assert.Equal(t, test.wantAccountID, result.Analysis["account_id"])
			assert.Equal(t, "2026-09-05T00:00:00Z", result.Analysis["not_before"])
			assert.Equal(t, "2026-09-05T23:59:59Z", result.Analysis["expires_on"])
		})
	}
}

func TestCloudflareAccountIDV1(t *testing.T) {
	rule := CloudflareAccountIDV1()
	assert.True(t, rule.SkipReport)

	tests := []struct {
		value string
		match bool
	}{
		{value: `account_id=00000000000000000000000000000000`, match: true},
		{value: `CLOUDFLARE_ACCOUNT_ID=11111111111111111111111111111111`, match: true},
		{value: `accountId: "22222222222222222222222222222222"`, match: true},
		{value: `cloudflare account id = 33333333333333333333333333333333`, match: true},
		{value: `cloudflare_access_key_id=44444444444444444444444444444444`},
	}

	for _, test := range tests {
		matches := rule.Regex.FindStringSubmatch(test.value)
		if !test.match {
			assert.Empty(t, matches, test.value)
			continue
		}
		require.Len(t, matches, 2, test.value)
	}
}

func TestCloudflareAPIKeyAnalysis(t *testing.T) {
	tests := []struct {
		name             string
		input            map[string]any
		wantPath         string
		statusCode       int
		body             string
		wantSeverity     report.Severity
		wantCapabilities []report.Capability
		wantPermissions  []any
		wantAccountID    string
		wantReason       string
	}{
		{
			name:       "user read permission",
			input:      map[string]any{"token_id": "user-token-id", "token_type": "user"},
			wantPath:   "/client/v4/user/tokens/user-token-id",
			statusCode: http.StatusOK,
			body: `{"success":true,"result":{"name":"dns-reader","policies":[
  {"effect":"allow","permission_groups":[{"name":"Zone Read"}]},
  {"effect":"deny","permission_groups":[{"name":"Account Settings Write"}]}
]}}`,
			wantSeverity:     report.SeverityMedium,
			wantCapabilities: []report.Capability{report.CapabilityRead},
			wantPermissions:  []any{"Zone Read"},
		},
		{
			name: "account privileged permissions",
			input: map[string]any{
				"token_id": "account-token-id", "token_type": "account",
				"account_id": "account-id",
			},
			wantPath:   "/client/v4/accounts/account-id/tokens/account-token-id",
			statusCode: http.StatusOK,
			body: `{"success":true,"result":{"name":"r2-deploy","policies":[{"effect":"allow","permission_groups":[
  {"name":"Workers R2 Storage Bucket Item Write"},
  {"name":"Account API Tokens Write"},
  {"name":"Memberships Write"}
]}]}}`,
			wantSeverity: report.SeverityHigh,
			wantCapabilities: []report.Capability{
				report.CapabilityRead,
				report.CapabilityWrite,
				report.CapabilityCreateCredentials,
				report.CapabilityManageUsers,
			},
			wantPermissions: []any{
				"Workers R2 Storage Bucket Item Write",
				"Account API Tokens Write",
				"Memberships Write",
			},
			wantAccountID: "account-id",
		},
		{
			name:             "policy details unavailable",
			input:            map[string]any{"token_id": "user-token-id", "token_type": "user"},
			wantPath:         "/client/v4/user/tokens/user-token-id",
			statusCode:       http.StatusForbidden,
			body:             `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`,
			wantSeverity:     report.SeverityUnknown,
			wantCapabilities: []report.Capability{},
			wantPermissions:  []any{},
			wantReason:       "Cloudflare did not allow this token to read its policy details",
		},
		{
			name:             "empty policy set",
			input:            map[string]any{"token_id": "empty-token-id", "token_type": "user"},
			wantPath:         "/client/v4/user/tokens/empty-token-id",
			statusCode:       http.StatusOK,
			body:             `{"success":true,"result":{"name":"empty","policies":[]}}`,
			wantSeverity:     report.SeverityLow,
			wantCapabilities: []report.Capability{},
			wantPermissions:  []any{},
		},
		{
			name:             "action-only permission",
			input:            map[string]any{"token_id": "purge-token-id", "token_type": "user"},
			wantPath:         "/client/v4/user/tokens/purge-token-id",
			statusCode:       http.StatusOK,
			body:             `{"success":true,"result":{"policies":[{"effect":"allow","permission_groups":[{"name":"Cache Purge"}]}]}}`,
			wantSeverity:     report.SeverityHigh,
			wantCapabilities: []report.Capability{report.CapabilityWrite},
			wantPermissions:  []any{"Cache Purge"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, err := exprruntime.New(&http.Client{Transport: cloudflareFixtureTransport(func(request *http.Request) (*http.Response, error) {
				assert.Equal(t, test.wantPath, request.URL.Path)
				assert.Equal(t, "Bearer fixture-secret", request.Header.Get("Authorization"))
				return cloudflareResponse(test.statusCode, test.body), nil
			})})
			require.NoError(t, err)

			program, err := runtime.CompileAnalysis(cloudflareAPITokenAnalyzeExpr)
			require.NoError(t, err)
			value, err := runtime.EvalAnalysisWithComponents(
				t.Context(), program,
				map[string]string{"rule_id": "cloudflare-api-key.2", "secret": "fixture-secret"},
				nil, nil, nil,
				map[string]any{"status": "valid", "reason": "", "metadata": map[string]any{}, "analysis": test.input},
				exprruntime.EvalOptions{},
			)
			require.NoError(t, err)
			result, err := analyze.ParseResult(value.Value)
			require.NoError(t, err)

			assert.Equal(t, test.wantSeverity, result.Severity)
			assert.Equal(t, test.wantCapabilities, result.Capabilities)
			assert.Equal(t, test.wantPermissions, result.Metadata["permissions"])
			assert.Equal(t, test.wantReason, result.Reason)
			if test.wantAccountID != "" {
				require.NotNil(t, result.Identity)
				require.NotNil(t, result.Identity.Account)
				assert.Equal(t, test.wantAccountID, result.Identity.Account.ID)
			}
		})
	}
}

func cloudflareResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
