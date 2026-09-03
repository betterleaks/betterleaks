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
			body:             `{"id":9,"name":"automation","user_id":1140645,"scopes":["api"],"granular":false}`,
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
			assert.Empty(t, validationResult.Metadata)
			if test.wantTokenID != "" {
				assert.Equal(t, test.wantTokenID, validationResult.Analysis["token_id"])
				assert.Equal(t, false, validationResult.Analysis["granular"])
				assert.Equal(t, []any{"api"}, validationResult.Analysis["scopes"])
				assert.NotContains(t, validationResult.Analysis, "granular_scopes")
			}

			analysisProgram, err := runtime.CompileAnalysis(test.analysis)
			require.NoError(t, err)
			analysisValue, err := runtime.EvalAnalysisWithComponents(
				t.Context(), analysisProgram, finding, nil, nil, nil,
				map[string]any{
					"status":   string(validationResult.Status),
					"reason":   validationResult.Reason,
					"metadata": validationResult.Metadata,
					"analysis": validationResult.Analysis,
				},
				exprruntime.EvalOptions{},
			)
			require.NoError(t, err)
			analysisResult, err := analyze.ParseResult(analysisValue.Value)
			require.NoError(t, err)
			assert.Equal(t, test.wantCapabilities, analysisResult.Capabilities)
			assert.NotEmpty(t, analysisResult.Metadata)
			require.NotNil(t, analysisResult.Identity)
			assert.Equal(t, test.wantIdentity, analysisResult.Identity.ID)
		})
	}
}

func TestCredentialAnalysisMappings(t *testing.T) {
	tests := []struct {
		name         string
		expression   string
		input        map[string]any
		severity     report.Severity
		capabilities []report.Capability
		identityID   string
		accountID    string
	}{
		{
			name:       "airtable",
			expression: airtableAnalyzeExpr,
			input: map[string]any{
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
			input: map[string]any{
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
			input: map[string]any{
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
			input: map[string]any{
				"user_id": "U123", "user": "octo", "team_id": "T123", "team": "Acme",
				"scopes": []any{"channels:history", "chat:write", "admin.users:write"},
			},
			severity:     report.SeverityCritical,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityManageUsers},
			identityID:   "U123", accountID: "T123",
		},
		{
			name:       "github",
			expression: githubTokenAnalyzeExpr,
			input: map[string]any{
				"id": "7", "username": "octocat", "scopes": []any{"repo", "admin:public_key"},
			},
			severity:     report.SeverityCritical,
			capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityCreateCredentials},
			identityID:   "7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateProviderAnalysis(t, test.expression, test.input)
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

func TestCredentialAnalysisRegexScopeFamilies(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		scopes     any
		want       []report.Capability
	}{
		{
			name:       "airtable read suffix",
			expression: airtableAnalyzeExpr,
			scopes:     []any{"future.resource:read"},
			want:       []report.Capability{report.CapabilityRead},
		},
		{
			name:       "github read and write prefixes",
			expression: githubTokenAnalyzeExpr,
			scopes:     []any{"read:future_resource", "write:future_resource"},
			want:       []report.Capability{report.CapabilityRead, report.CapabilityWrite},
		},
		{
			name:       "slack read and write suffixes",
			expression: slackAnalyzeExpr,
			scopes:     []any{"canvas:read", "canvas:write"},
			want:       []report.Capability{report.CapabilityRead, report.CapabilityWrite},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateProviderAnalysis(t, test.expression, map[string]any{"scopes": test.scopes})
			assert.Equal(t, test.want, result.Capabilities)
		})
	}
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
	assert.Equal(t, []any{
		"create_access_request",
		"read_personal_access_token",
		"read_deploy_key",
		"create_email",
	}, result.Metadata["permissions"])

	result = evaluateProviderAnalysis(t, gitlabPatAnalyzeExpr, map[string]any{
		"user_id": "42",
		"scopes":  []any{"read_future_resource", "write_future_resource"},
	})

	assert.Equal(t, report.SeverityHigh, result.Severity)
	assert.Equal(t, []report.Capability{report.CapabilityRead, report.CapabilityWrite}, result.Capabilities)
	assert.Equal(t, []any{"read_future_resource", "write_future_resource"}, result.Metadata["permissions"])
}

func TestGitLabAnalysisExplainsMissingFineGrainedPermissionDetails(t *testing.T) {
	result := evaluateProviderAnalysis(t, gitlabPatAnalyzeExpr, map[string]any{
		"user_id":  "1140645",
		"scopes":   []any{"granular"},
		"granular": true,
	})

	assert.Equal(t, report.SeverityUnknown, result.Severity)
	assert.Equal(t, "GitLab did not return fine-grained permission details", result.Reason)
	require.NotNil(t, result.Identity)
	assert.Equal(t, "1140645", result.Identity.ID)
	assert.Empty(t, result.Capabilities)
}

func TestGitLabValidationKeepsGranularInputPrivate(t *testing.T) {
	runtime, err := exprruntime.New(&http.Client{Transport: analysisFixtureTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"id":27109975,"name":"granular","user_id":1140645,"scopes":["granular"],"granular":true}`,
			)),
		}, nil
	})})
	require.NoError(t, err)

	program, err := runtime.CompileValidation(gitlabPatExpr)
	require.NoError(t, err)
	value, err := runtime.EvalValidation(
		t.Context(),
		program,
		map[string]string{"rule_id": "gitlab-pat", "secret": "fixture-secret"},
		nil,
		nil,
		exprruntime.EvalOptions{},
	)
	require.NoError(t, err)
	result := validatepkg.ParseResult(value.Value)

	assert.Equal(t, report.ValidationStatusValid, result.Status)
	assert.Empty(t, result.Metadata)
	assert.Equal(t, true, result.Analysis["granular"])
	assert.Nil(t, result.Analysis["scopes"])
}

func TestGitLabAnalysisLooksUpMissingFineGrainedPermissionDetails(t *testing.T) {
	var requests []string
	runtime, err := exprruntime.New(&http.Client{Transport: analysisFixtureTransport(func(request *http.Request) (*http.Response, error) {
		requestURI := request.URL.RequestURI()
		requests = append(requests, requestURI)
		assert.Equal(t, "/api/v4/personal_access_tokens?user_id=1140645&state=active&per_page=100", requestURI)
		assert.Equal(t, "fixture-secret", request.Header.Get("PRIVATE-TOKEN"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`[{"id":7,"granular_scopes":[{"permissions":["future_permission"]}]},{"id":27109975,"granular_scopes":[{"permissions":["read_job"]}]}]`,
			)),
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
			"status":   "valid",
			"reason":   "",
			"metadata": map[string]any{},
			"analysis": map[string]any{
				"token_id": "27109975",
				"user_id":  "1140645",
				"scopes":   []any{"granular"},
				"granular": true,
			},
		},
		exprruntime.EvalOptions{},
	)
	require.NoError(t, err)
	result, err := analyze.ParseResult(value.Value)
	require.NoError(t, err)

	assert.Equal(t, []report.Capability{report.CapabilityRead}, result.Capabilities)
	assert.Empty(t, result.Reason)
	assert.Equal(t, []any{"read_job"}, result.Metadata["permissions"])
	assert.Equal(t, []string{"/api/v4/personal_access_tokens?user_id=1140645&state=active&per_page=100"}, requests)
}

func evaluateProviderAnalysis(t *testing.T, expression string, input map[string]any) report.Analysis {
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
		map[string]any{"status": "valid", "reason": "", "metadata": map[string]any{}, "analysis": input},
		exprruntime.EvalOptions{},
	)
	require.NoError(t, err)
	analysisResult, err := analyze.ParseResult(result.Value)
	require.NoError(t, err)
	return analysisResult
}
