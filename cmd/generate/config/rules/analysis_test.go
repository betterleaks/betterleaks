package rules

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/internal/analyze"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	validatepkg "github.com/betterleaks/betterleaks/v2/internal/validate"
	"github.com/betterleaks/betterleaks/v2/report"
)

type analysisFixtureTransport func(*http.Request) (*http.Response, error)

func (transport analysisFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestCredentialAnalysisProviderFixtures(t *testing.T) {
	tests := []struct {
		name             string
		validation       string
		analysis         string
		body             string
		headers          http.Header
		wantCapabilities []report.Capability
		wantIdentity     string
		wantTokenID      string
	}{
		{
			name:             "airtable",
			validation:       airtableValidateExpr,
			analysis:         airtableAnalyzeExpr,
			body:             `{"id":"usrAirtable","email":"owner@example.com","scopes":["data.records:read","schema.bases:write"]}`,
			wantCapabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite},
			wantIdentity:     "usrAirtable",
		},
		{
			name:             "gitlab",
			validation:       gitlabPatExpr,
			analysis:         gitlabPatAnalyzeExpr,
			body:             `{"id":9,"name":"automation","user_id":1140645,"scopes":["api"],"granular":false,"granular_scopes":[]}`,
			wantCapabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite},
			wantIdentity:     "1140645",
			wantTokenID:      "9",
		},
		{
			name:             "hugging-face",
			validation:       huggingFaceValidateExpr,
			analysis:         huggingFaceAnalyzeExpr,
			body:             `{"id":"userHF","name":"octo","fullname":"Octo Cat","email":"octo@example.com","orgs":[],"auth":{"accessToken":{"role":"read"}}}`,
			wantCapabilities: []report.Capability{report.CapabilityRead},
			wantIdentity:     "userHF",
		},
		{
			name:             "slack",
			validation:       slackValidateExpr,
			analysis:         slackAnalyzeExpr,
			body:             `{"ok":true,"team":"Acme","team_id":"T123","user":"octo","user_id":"U123"}`,
			headers:          http.Header{"X-Oauth-Scopes": []string{"channels:history,chat:write"}},
			wantCapabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite},
			wantIdentity:     "U123",
		},
		{
			name:             "github",
			validation:       githubTokenExpr,
			analysis:         githubTokenAnalyzeExpr,
			body:             `{"id":7,"login":"octocat","name":"Octo Cat","email":"octo@example.com"}`,
			headers:          http.Header{"X-Oauth-Scopes": []string{"repo, read:org"}},
			wantCapabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite},
			wantIdentity:     "7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, err := exprruntime.New(&http.Client{Transport: analysisFixtureTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     test.headers,
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})})
			require.NoError(t, err)

			validationProgram, err := runtime.CompileValidation(test.validation)
			require.NoError(t, err)
			finding := map[string]string{"rule_id": test.name, "secret": "fixture-secret"}
			validationValue, err := runtime.EvalValidation(t.Context(), validationProgram, finding, nil, nil, exprruntime.EvalOptions{})
			require.NoError(t, err)
			validationResult := validatepkg.ParseResult(validationValue.Value)
			require.Equal(t, report.ValidationStatusValid, validationResult.Status)
			if test.wantTokenID != "" {
				assert.Equal(t, test.wantTokenID, validationResult.Metadata["token_id"])
			}

			analysisProgram, err := runtime.CompileAnalysis(test.analysis)
			require.NoError(t, err)
			analysisValue, err := runtime.EvalAnalysisWithComponents(
				t.Context(), analysisProgram, finding, nil, nil, nil,
				map[string]any{
					"status":   string(validationResult.Status),
					"reason":   validationResult.Reason,
					"metadata": validationResult.Metadata,
				},
				exprruntime.EvalOptions{},
			)
			require.NoError(t, err)
			analysisResult, err := analyze.ParseResult(analysisValue.Value)
			require.NoError(t, err)
			assert.Equal(t, test.wantCapabilities, analysisResult.Capabilities)
			require.NotNil(t, analysisResult.Identity)
			assert.Equal(t, test.wantIdentity, analysisResult.Identity.ID)
		})
	}
}

func TestCredentialAnalysisMappings(t *testing.T) {
	tests := []struct {
		name         string
		expression   string
		metadata     map[string]any
		severity     report.Severity
		capabilities []report.Capability
		identityID   string
		accountID    string
	}{
		{
			name:       "airtable",
			expression: airtableAnalyzeExpr,
			metadata: map[string]any{
				"id": "usrAirtable", "email": "owner@example.com",
				"scopes": []any{"data.records:read", "schema.bases:write", "enterprise.user:write"},
			},
			severity:     report.SeverityCritical,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityManageUsers},
			identityID:   "usrAirtable",
		},
		{
			name:       "gitlab",
			expression: gitlabPatAnalyzeExpr,
			metadata: map[string]any{
				"user_id": "42",
				"scopes":  []any{"api", "self_rotate"},
				"granular_scopes": []any{
					map[string]any{"permissions": []any{"read_job"}},
				},
			},
			severity:     report.SeverityCritical,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityCreateCredentials},
			identityID:   "42",
		},
		{
			name:       "hugging-face",
			expression: huggingFaceAnalyzeExpr,
			metadata: map[string]any{
				"id": "userHF", "username": "octo", "name": "Octo Cat",
				"auth": map[string]any{"accessToken": map[string]any{"role": "write"}},
				"orgs": []any{map[string]any{"id": "orgHF", "name": "Acme"}},
			},
			severity:     report.SeverityHigh,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite},
			identityID:   "userHF", accountID: "orgHF",
		},
		{
			name:       "slack",
			expression: slackAnalyzeExpr,
			metadata: map[string]any{
				"user_id": "U123", "user": "octo", "team_id": "T123", "team": "Acme",
				"scopes": "channels:history, chat:write, admin.users:write",
			},
			severity:     report.SeverityCritical,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityManageUsers},
			identityID:   "U123", accountID: "T123",
		},
		{
			name:       "github",
			expression: githubTokenAnalyzeExpr,
			metadata: map[string]any{
				"id": "7", "username": "octocat", "scopes": "repo, admin:public_key",
			},
			severity:     report.SeverityCritical,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityCreateCredentials},
			identityID:   "7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateProviderAnalysis(t, test.expression, test.metadata)
			assert.Equal(t, test.severity, result.Severity)
			assert.Equal(t, test.capabilities, result.Capabilities)
			require.NotNil(t, result.Identity)
			assert.Equal(t, test.identityID, result.Identity.ID)
			if test.accountID != "" {
				require.NotNil(t, result.Identity.Account)
				assert.Equal(t, test.accountID, result.Identity.Account.ID)
			}
		})
	}
}

func TestCredentialAnalysisUnknownGrantsStayUnknown(t *testing.T) {
	result := evaluateProviderAnalysis(t, gitlabPatAnalyzeExpr, map[string]any{
		"user_id": "42",
		"granular_scopes": []any{
			map[string]any{"permissions": []any{"future_permission"}},
		},
	})
	assert.Equal(t, report.SeverityUnknown, result.Severity)
	assert.Empty(t, result.Capabilities)

	result = evaluateProviderAnalysis(t, huggingFaceAnalyzeExpr, map[string]any{
		"id":   "userHF",
		"auth": map[string]any{"accessToken": map[string]any{"role": "fineGrained"}},
	})
	assert.Equal(t, report.SeverityUnknown, result.Severity)
	assert.Equal(t, "Fine-grained or unknown token role was not expanded", result.Reason)
	assert.Empty(t, result.Capabilities)
}

func TestGitLabAnalysisClassifiesGranularPermissionActions(t *testing.T) {
	result := evaluateProviderAnalysis(t, gitlabPatAnalyzeExpr, map[string]any{
		"user_id": "42",
		"granular_scopes": []any{
			map[string]any{
				"access": "user",
				"permissions": []any{
					"create_access_request",
					"read_personal_access_token",
					"read_deploy_key",
					"create_email",
				},
			},
		},
	})

	assert.Equal(t, report.SeverityHigh, result.Severity)
	assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, result.Capabilities)

	result = evaluateProviderAnalysis(t, gitlabPatAnalyzeExpr, map[string]any{
		"user_id": "42",
		"scopes":  []any{"read_future_resource", "write_future_resource"},
	})

	assert.Equal(t, report.SeverityHigh, result.Severity)
	assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, result.Capabilities)
}

func TestGitLabAnalysisExplainsMissingFineGrainedPermissionDetails(t *testing.T) {
	result := evaluateProviderAnalysis(t, gitlabPatAnalyzeExpr, map[string]any{
		"user_id":         "1140645",
		"scopes":          []any{"granular"},
		"granular":        true,
		"granular_scopes": []any{},
	})

	assert.Equal(t, report.SeverityUnknown, result.Severity)
	assert.Equal(t, "GitLab did not return fine-grained permission details", result.Reason)
	require.NotNil(t, result.Identity)
	assert.Equal(t, "1140645", result.Identity.ID)
	assert.Empty(t, result.Capabilities)
}

func TestGitLabAnalysisLooksUpMissingFineGrainedPermissionDetails(t *testing.T) {
	tests := []struct {
		name         string
		responses    map[string]string
		wantRequests []string
	}{
		{
			name: "token detail",
			responses: map[string]string{
				"/api/v4/personal_access_tokens/27109975": `{"id":27109975,"granular_scopes":[{"permissions":["read_job"]}]}`,
			},
			wantRequests: []string{"/api/v4/personal_access_tokens/27109975"},
		},
		{
			name: "token list fallback",
			responses: map[string]string{
				"/api/v4/personal_access_tokens/27109975":                     `{"id":27109975,"granular_scopes":[]}`,
				"/api/v4/personal_access_tokens?user_id=1140645&per_page=100": `[{"id":7,"granular_scopes":[{"permissions":["future_permission"]}]},{"id":27109975,"granular_scopes":[{"permissions":["read_job"]}]}]`,
			},
			wantRequests: []string{
				"/api/v4/personal_access_tokens/27109975",
				"/api/v4/personal_access_tokens?user_id=1140645&per_page=100",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests []string
			runtime, err := exprruntime.New(&http.Client{Transport: analysisFixtureTransport(func(request *http.Request) (*http.Response, error) {
				requestURI := request.URL.RequestURI()
				requests = append(requests, requestURI)
				body, ok := test.responses[requestURI]
				require.Truef(t, ok, "unexpected request %s", requestURI)
				assert.Equal(t, "fixture-secret", request.Header.Get("PRIVATE-TOKEN"))
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
				}, nil
			})})
			require.NoError(t, err)

			program, err := runtime.CompileAnalysis(gitlabPatAnalyzeExpr)
			require.NoError(t, err)
			value, err := runtime.EvalAnalysisWithComponents(
				t.Context(),
				program,
				map[string]string{"rule_id": "gitlab-pat", "secret": "fixture-secret"},
				nil,
				nil,
				nil,
				map[string]any{
					"status": "valid",
					"reason": "",
					"metadata": map[string]any{
						"token_id":        "27109975",
						"user_id":         "1140645",
						"scopes":          []any{"granular"},
						"granular":        true,
						"granular_scopes": []any{},
					},
				},
				exprruntime.EvalOptions{},
			)
			require.NoError(t, err)
			result, err := analyze.ParseResult(value.Value)
			require.NoError(t, err)

			assert.Equal(t, []report.Capability{report.CapabilityRead}, result.Capabilities)
			assert.Empty(t, result.Reason)
			assert.Equal(t, test.wantRequests, requests)
		})
	}
}

func evaluateProviderAnalysis(t *testing.T, expression string, metadata map[string]any) report.Analysis {
	t.Helper()
	runtime, err := exprruntime.New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileAnalysis(expression)
	require.NoError(t, err)
	result, err := runtime.EvalAnalysisWithComponents(
		t.Context(),
		program,
		map[string]string{"rule_id": "test-rule", "secret": "test-secret"},
		nil,
		nil,
		nil,
		map[string]any{"status": "valid", "reason": "", "metadata": metadata},
		exprruntime.EvalOptions{},
	)
	require.NoError(t, err)
	analysisResult, err := analyze.ParseResult(result.Value)
	require.NoError(t, err)
	return analysisResult
}
