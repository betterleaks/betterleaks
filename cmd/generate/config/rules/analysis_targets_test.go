package rules

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	analysisresult "github.com/betterleaks/betterleaks/v2/internal/analyze"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/provider"
	"github.com/betterleaks/betterleaks/v2/report"
)

type targetFixture struct {
	rule                             func() *config.Rule
	url, authHeader, authValue, body string
	identity                         *report.AnalysisIdentity
	capabilities                     []report.Capability
}

// These are synthetic responses based on the provider references in each rule,
// not captures from live credentials. Extra secret fields exercise allowlisting.
func analysisTargetFixtures() []targetFixture {
	return []targetFixture{
		{ApifyAPIToken, "https://api.apify.com/v2/users/me", "Authorization", "Bearer fixture-secret-us20", `{"data":{"id":"apify-user","username":"alex","email":"alex@example.com","proxy":{"password":"unexpected-secret"}}}`, &report.AnalysisIdentity{ID: "apify-user", Username: "alex", Email: "alex@example.com"}, nil},
		{BitlyAccessToken, "https://api-ssl.bitly.com/v4/user", "Authorization", "Bearer fixture-secret-us20", `{"login":"alex","name":"Alex","emails":[{"email":"other@example.com","is_primary":false},{"email":"alex@example.com","is_primary":true}],"default_group_guid":"group-1"}`, &report.AnalysisIdentity{Username: "alex", Name: "Alex", Email: "alex@example.com"}, nil},
		{BoxAPIAccessToken, "https://api.box.com/2.0/users/me", "Authorization", "Bearer fixture-secret-us20", `{"id":"box-user","name":"Alex","login":"alex@example.com","role":"admin"}`, &report.AnalysisIdentity{ID: "box-user", Name: "Alex", Email: "alex@example.com"}, nil},
		{CircleCIPersonalToken, "https://circleci.com/api/v2/me", "Circle-Token", "fixture-secret-us20", `{"id":"circle-user","login":"alex","name":"Alex"}`, &report.AnalysisIdentity{ID: "circle-user", Username: "alex", Name: "Alex"}, nil},
		{ClickUpPersonalAPIToken, "https://api.clickup.com/api/v2/user", "Authorization", "fixture-secret-us20", `{"user":{"id":12345,"username":"alex","email":"alex@example.com"}}`, &report.AnalysisIdentity{ID: "12345", Username: "alex", Email: "alex@example.com"}, nil},
		{FigmaPersonalAccessToken, "https://api.figma.com/v1/me", "X-Figma-Token", "fixture-secret-us20", `{"id":"figma-user","handle":"alex","email":"alex@example.com"}`, &report.AnalysisIdentity{ID: "figma-user", Username: "alex", Email: "alex@example.com"}, nil},
		{FigmaPersonalAccessHeaderToken, "https://api.figma.com/v1/me", "X-Figma-Token", "fixture-secret-us20", `{"id":"figma-user","handle":"alex","email":"alex@example.com"}`, &report.AnalysisIdentity{ID: "figma-user", Username: "alex", Email: "alex@example.com"}, nil},
		{LinearAPIToken, "https://api.linear.app/graphql", "Authorization", "fixture-secret-us20", `{"data":{"viewer":{"id":"linear-user","name":"Alex","email":"alex@example.com"}}}`, &report.AnalysisIdentity{ID: "linear-user", Name: "Alex", Email: "alex@example.com"}, nil},
		{Replicate, "https://api.replicate.com/v1/account", "Authorization", "Bearer fixture-secret-us20", `{"type":"organization","username":"acme","name":"Acme"}`, &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "acme", Name: "Acme"}}, nil},
		{MailChimp, "https://us20.api.mailchimp.com/3.0/", "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("x:fixture-secret-us20")), `{"account_id":"mc-account","account_name":"Acme","username":"alex","email":"alex@example.com","role":"owner"}`, &report.AnalysisIdentity{Username: "alex", Email: "alex@example.com", Account: &report.AnalysisAccount{ID: "mc-account", Name: "Acme"}}, nil},
		{SendInBlueAPIToken, "https://api.brevo.com/v3/account", "api-key", "fixture-secret-us20", `{"organization_id":"brevo-org","user_id":42,"companyName":"Acme","email":"alex@example.com","firstName":"Alex","lastName":"Smith","marketingAutomation":{"key":"unexpected-secret"},"plan":[{"type":"paid","credits":10000}]}`, &report.AnalysisIdentity{ID: "42", Name: "Alex Smith", Email: "alex@example.com", Account: &report.AnalysisAccount{ID: "brevo-org", Name: "Acme"}}, nil},
		{HunterAPIKey, "https://api.hunter.io/v2/account", "X-API-KEY", "fixture-secret-us20", `{"data":{"email":"alex@example.com","first_name":"Alex","last_name":"Smith","plan_name":"Starter"}}`, &report.AnalysisIdentity{Name: "Alex Smith", Email: "alex@example.com"}, nil},
		{WakaTimeAPIKeyV1, "https://api.wakatime.com/api/v1/users/current?api_key=fixture-secret-us20", "", "", `{"data":{"id":"waka-user","username":"alex","display_name":"Alex","email":"alex@example.com"}}`, &report.AnalysisIdentity{ID: "waka-user", Username: "alex", Name: "Alex", Email: "alex@example.com"}, nil},
		{WakaTimeAPIKeyV2, "https://api.wakatime.com/api/v1/users/current?api_key=fixture-secret-us20", "", "", `{"data":{"id":"waka-user","username":"alex","display_name":"Alex","email":"alex@example.com"}}`, &report.AnalysisIdentity{ID: "waka-user", Username: "alex", Name: "Alex", Email: "alex@example.com"}, nil},
		{MiroAccessToken, "https://api.miro.com/v1/oauth-token", "Authorization", "Bearer fixture-secret-us20", `{"type":"access-token","user":{"id":"miro-user","name":"Alex"},"team":{"id":"miro-team","name":"Team"},"organization":{"id":"miro-org","name":"Acme"},"scopes":["boards:read","boards:write"]}`, &report.AnalysisIdentity{ID: "miro-user", Name: "Alex", Account: &report.AnalysisAccount{ID: "miro-org", Name: "Acme"}}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
		{SendGridAPIToken, "https://api.sendgrid.com/v3/scopes", "Authorization", "Bearer fixture-secret-us20", `{"scopes":["mail.send","api_keys.read","api_keys.create","teammates.update"]}`, nil, []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityCreateCredentials, report.CapabilityManageUsers}},
		{TwitchAPIToken, "https://id.twitch.tv/oauth2/validate", "Authorization", "OAuth fixture-secret-us20", `{"client_id":"twitch-client","user_id":"twitch-user","login":"alex","scopes":["user:read:chat","user:write:chat"],"expires_in":300}`, &report.AnalysisIdentity{ID: "twitch-user", Username: "alex"}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
		{XAI, "https://api.x.ai/v1/api-key", "Authorization", "Bearer fixture-secret-us20", `{"api_key_id":"xai-key","user_id":"xai-user","team_id":"xai-team","name":"Automation","acls":["api-key:endpoint:*","api-key:model:*"],"api_key_disabled":false,"api_key_blocked":false,"team_blocked":false,"redacted_api_key":"unexpected-secret"}`, &report.AnalysisIdentity{ID: "xai-user", Account: &report.AnalysisAccount{ID: "xai-team"}}, nil},
		{OpenRouter, "https://openrouter.ai/api/v1/key", "Authorization", "Bearer fixture-secret-us20", `{"data":{"label":"unexpected-secret","creator_user_id":"or-user","organization_id":"or-org","workspace_id":"workspace","is_management_key":true,"limit":0,"limit_remaining":0,"usage":0}}`, &report.AnalysisIdentity{ID: "or-user", Account: &report.AnalysisAccount{ID: "or-org"}}, []report.Capability{report.CapabilityCreateCredentials}},
		{FullStoryAPIKey, "https://api.fullstory.com/me", "Authorization", "Basic fixture-secret-us20", `{"role":"ADMIN"}`, nil, []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityAdmin}},
	}
}

func TestAnalysisTargetsProviderFixtures(t *testing.T) {
	for _, fixture := range analysisTargetFixtures() {
		rule := fixture.rule()
		t.Run(rule.ID, func(t *testing.T) {
			// Every provider must ignore unrelated newly returned credentials.
			var payload map[string]any
			require.NoError(t, json.Unmarshal([]byte(fixture.body), &payload))
			payload["access_token"] = "unexpected-secret"
			payload["api_secret"] = "unexpected-secret"
			body, err := json.Marshal(payload)
			require.NoError(t, err)
			result, analysis := runTargetFixture(t, rule, fixture, http.StatusOK, string(body), true)
			assert.Equal(t, report.ValidationStatusValid, result.Status)
			assert.Equal(t, fixture.identity, analysis.Identity)
			assert.ElementsMatch(t, fixture.capabilities, analysis.Capabilities)
			assert.Equal(t, report.AnalysisSeverity(fixture.capabilities), analysis.Severity)
			output, err := json.Marshal([]any{result.Analysis, result.Metadata, analysis})
			require.NoError(t, err)
			assert.NotContains(t, string(output), "unexpected-secret", "only allowlisted fields may leave validation")
		})
	}
}

func runTargetFixture(t *testing.T, rule *config.Rule, fixture targetFixture, status int, body string, analyze bool) (*provider.Result, report.Analysis) {
	t.Helper()
	calls := 0
	runtime, err := exprruntime.New(&http.Client{Transport: analysisFixtureTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, 1, calls, "analysis must reuse validation and never probe extra endpoints")
		assert.Equal(t, fixture.url, req.URL.String())
		if fixture.authHeader != "" {
			assert.Equal(t, fixture.authValue, req.Header.Get(fixture.authHeader))
		}
		if rule.ID == "linear-api-key" {
			assert.Equal(t, http.MethodPost, req.Method)
			raw, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.JSONEq(t, `{"query":"query { viewer { id name email } }"}`, string(raw))
		} else {
			assert.Equal(t, http.MethodGet, req.Method)
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	require.NoError(t, err)
	program, err := runtime.CompileValidation(rule.ValidateExpr)
	require.NoError(t, err)
	finding := map[string]string{"rule_id": rule.ID, "secret": "fixture-secret-us20"}
	value, err := runtime.EvalValidation(t.Context(), program, finding, nil, nil, exprruntime.EvalOptions{})
	require.NoError(t, err)
	result := provider.ParseResult(value.Value)
	if !analyze {
		return result, report.Analysis{}
	}
	require.Equal(t, report.ValidationStatusValid, result.Status)
	program, err = runtime.CompileAnalysis(rule.AnalyzeExpr)
	require.NoError(t, err)
	value, err = runtime.EvalAnalysisWithComponents(t.Context(), program, finding, nil, nil, nil, map[string]any{"analysis": result.Analysis, "metadata": result.Metadata, "status": string(result.Status)}, exprruntime.EvalOptions{})
	require.NoError(t, err)
	analysis, err := analysisresult.ParseResult(value.Value)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	return result, analysis
}

func TestAnalysisTargetsRejectUnprovenAuthentication(t *testing.T) {
	for _, fixture := range analysisTargetFixtures() {
		rule := fixture.rule()
		for _, test := range []struct {
			name   string
			status int
			body   string
			want   report.ValidationStatus
		}{
			{"unauthorized", 401, fixture.body, report.ValidationStatusInvalid},
			{"scope or policy denied", 403, fixture.body, report.ValidationStatusUnknown},
			{"rate limited", 429, fixture.body, report.ValidationStatusUnknown},
			{"server error", 500, fixture.body, report.ValidationStatusUnknown},
			{"empty object", 200, `{}`, report.ValidationStatusUnknown},
			{"null", 200, `null`, report.ValidationStatusUnknown},
			{"array", 200, `[]`, report.ValidationStatusUnknown},
			{"malformed JSON", 200, `<html>login required</html>`, report.ValidationStatusUnknown},
		} {
			t.Run(rule.ID+"/"+test.name, func(t *testing.T) {
				result, _ := runTargetFixture(t, rule, fixture, test.status, test.body, false)
				assert.Equal(t, test.want, result.Status)
				assert.Empty(t, result.Analysis, "failed validation must not hand off grants")
			})
		}
	}
}

func TestAnalysisTargetsPermissionBoundaries(t *testing.T) {
	tests := []struct {
		name, expr string
		input      map[string]any
		want       []report.Capability
	}{
		{"Miro future scopes", miroAnalyzeExpr, map[string]any{"scopes": []any{"future:read", "future:write"}}, nil},
		{"Miro Web SDK scopes", miroAnalyzeExpr, map[string]any{"scopes": []any{"identity:write", "team:write", "microphone:listen"}}, nil},
		{"Miro team management", miroAnalyzeExpr, map[string]any{"scopes": []any{"organizations:teams:write"}}, []report.Capability{report.CapabilityWrite, report.CapabilityManageUsers}},
		{"SendGrid send only", sendgridAnalyzeExpr, map[string]any{"scopes": []any{"mail.send"}}, []report.Capability{report.CapabilityWrite}},
		{"SendGrid key metadata is not secret material", sendgridAnalyzeExpr, map[string]any{"scopes": []any{"api_keys.read"}}, []report.Capability{report.CapabilityRead}},
		{"SendGrid future scopes", sendgridAnalyzeExpr, map[string]any{"scopes": []any{"future.read", "future.admin", "future.write"}}, nil},
		{"Twitch app token", twitchAnalyzeExpr, map[string]any{"client_id": "app", "scopes": []any{}}, nil},
		{"Twitch stream key scope", twitchAnalyzeExpr, map[string]any{"scopes": []any{"channel:read:stream_key"}}, []report.Capability{report.CapabilityRead, report.CapabilityReadSecrets}},
		{"Twitch moderator grants", twitchAnalyzeExpr, map[string]any{"scopes": []any{"channel:manage:moderators"}}, []report.Capability{report.CapabilityWrite, report.CapabilityManageUsers}},
		{"xAI wildcards are not admin", xaiAnalyzeExpr, map[string]any{"acls": []any{"api-key:endpoint:*", "api-key:model:*"}}, nil},
		{"OpenRouter funded inference", openrouterAnalyzeExpr, map[string]any{"limit_remaining": 100, "is_management_key": false}, nil},
		{"OpenRouter omitted management flag", openrouterAnalyzeExpr, map[string]any{}, nil},
		{"OpenRouter management", openrouterAnalyzeExpr, map[string]any{"is_management_key": true}, []report.Capability{report.CapabilityCreateCredentials}},
		{"Fullstory Standard", fullstoryAnalyzeExpr, map[string]any{"role": "USER"}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
		{"Fullstory Architect", fullstoryAnalyzeExpr, map[string]any{"role": "ARCHITECT"}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
		{"Fullstory unknown role", fullstoryAnalyzeExpr, map[string]any{"role": "OWNER"}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateProviderAnalysis(t, test.expr, test.input)
			assert.ElementsMatch(t, test.want, result.Capabilities)
			assert.Equal(t, report.AnalysisSeverity(test.want), result.Severity)
			if len(test.want) == 0 {
				assert.NotEmpty(t, result.Reason)
			}
		})
	}
}

func TestAnalysisTargetsOptionalAndPartialResponses(t *testing.T) {
	fixtures := analysisTargetFixtures()
	for _, fixture := range fixtures {
		rule := fixture.rule()
		switch rule.ID {
		case "bitly-access-token":
			for _, body := range []string{`{"login":"alex"}`, `{"login":"alex","emails":null}`, `{"login":"alex","emails":[{"email":"wrong@example.com","is_primary":false}]}`} {
				_, analysis := runTargetFixture(t, rule, fixture, 200, body, true)
				require.NotNil(t, analysis.Identity)
				assert.Empty(t, analysis.Identity.Email)
				assert.Nil(t, analysis.Identity.Account)
			}
		case "linear-api-key":
			result, _ := runTargetFixture(t, rule, fixture, 200, `{"data":{"viewer":{"id":"alex"}},"errors":[{"message":"denied"}]}`, false)
			assert.Equal(t, report.ValidationStatusUnknown, result.Status)
			assert.Empty(t, result.Analysis)
		case "miro-access-token":
			_, analysis := runTargetFixture(t, rule, fixture, 200, `{"user":{"id":"alex"},"team":{"id":"team-1"},"scopes":null}`, true)
			require.NotNil(t, analysis.Identity.Account)
			assert.Equal(t, "team-1", analysis.Identity.Account.ID)
			assert.Empty(t, analysis.Capabilities)
			result, _ := runTargetFixture(t, rule, fixture, 400, `{"message":"Invalid token provided"}`, false)
			assert.Equal(t, report.ValidationStatusInvalid, result.Status)
		case "twitch-api-token":
			_, analysis := runTargetFixture(t, rule, fixture, 200, `{"client_id":"app-1","user_id":null,"login":null,"scopes":null,"expires_in":0}`, true)
			assert.Nil(t, analysis.Identity)
			assert.Empty(t, analysis.Capabilities)
			assert.Equal(t, float64(0), analysis.Metadata["expires_in"])
		case "openrouter-api-key":
			_, analysis := runTargetFixture(t, rule, fixture, 200, `{"data":{"label":"redacted","limit":null,"limit_remaining":0,"usage":0}}`, true)
			assert.Nil(t, analysis.Identity)
			assert.Equal(t, map[string]any{"expires_at": nil}, analysis.Metadata)
			assert.Empty(t, analysis.Capabilities)
			_, analysis = runTargetFixture(t, rule, fixture, 200, `{"data":{"label":"redacted","creator_user_id":"or-user","organization_id":null,"workspace_id":"personal-workspace","is_management_key":false,"is_free_tier":true,"limit":50,"limit_remaining":50,"limit_reset":null,"usage":0,"expires_at":"2026-09-21T16:11:44Z"}}`, true)
			assert.Equal(t, &report.AnalysisIdentity{ID: "or-user", Account: &report.AnalysisAccount{ID: "personal-workspace"}}, analysis.Identity)
			assert.Equal(t, map[string]any{"expires_at": "2026-09-21T16:11:44Z"}, analysis.Metadata)
			assert.Empty(t, analysis.Capabilities)
			assert.Equal(t, report.SeverityUnknown, analysis.Severity)
			_, analysis = runTargetFixture(t, rule, fixture, 200, fixture.body, true)
			assert.Equal(t, fixture.identity, analysis.Identity)
			assert.Equal(t, map[string]any{"expires_at": nil}, analysis.Metadata)
			assert.Equal(t, []report.Capability{report.CapabilityCreateCredentials}, analysis.Capabilities)
		case "xai-api-key":
			for _, flag := range []string{"api_key_disabled", "api_key_blocked", "team_blocked"} {
				body, err := json.Marshal(map[string]any{"api_key_id": "xai-key", flag: true})
				require.NoError(t, err)
				result, _ := runTargetFixture(t, rule, fixture, 200, string(body), false)
				assert.Equal(t, report.ValidationStatusInvalid, result.Status)
				assert.Contains(t, result.Reason, "disabled/blocked")
				assert.Equal(t, true, result.Metadata[flag])
				assert.Empty(t, result.Analysis)
			}
		case "sendgrid-api-token":
			_, analysis := runTargetFixture(t, rule, fixture, 200, `{"scopes":[]}`, true)
			assert.Empty(t, analysis.Capabilities)
			for _, body := range []string{`{"scopes":null}`, `{"scopes":"mail.send"}`, `{"scopes":["mail.send",42]}`} {
				result, _ := runTargetFixture(t, rule, fixture, 200, body, false)
				assert.Equal(t, report.ValidationStatusUnknown, result.Status)
			}
		}
	}
}
