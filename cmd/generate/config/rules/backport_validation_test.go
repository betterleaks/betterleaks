package rules

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/internal/validate"
	"github.com/betterleaks/betterleaks/report"
)

type ruleFixtureTransport func(*http.Request) (*http.Response, error)

func (f ruleFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Load the shipped config so these tests also exercise rule registration and
// generation, including v1 expression and validation-result compatibility.
func TestBackportedValidatorResponses(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	tests := []struct {
		id, url, method, header, auth, body string
		unauthorized                        report.ValidationStatus
	}{
		{"apify-api-token", "https://api.apify.com/v2/users/me", "GET", "Authorization", "Bearer fixture", `{"data":{"id":"u1","username":"tester"}}`, "invalid"},
		{"bitly-access-token", "https://api-ssl.bitly.com/v4/user", "GET", "Authorization", "Bearer fixture", `{"login":"tester","emails":[{"is_primary":true,"email":"test@example.com"}]}`, "invalid"},
		{"box-api-access-token", "https://api.box.com/2.0/users/me", "GET", "Authorization", "Bearer fixture", `{"id":"u1"}`, "invalid"},
		{"buildkite-user-access-token", "https://api.buildkite.com/v2/access-token", "GET", "Authorization", "Bearer fixture", `{"scopes":["read_user"]}`, "invalid"},
		{"circleci-personal-token", "https://circleci.com/api/v2/me", "GET", "Circle-Token", "fixture", `{"id":"u1"}`, "invalid"},
		{"clickup-personal-api-token", "https://api.clickup.com/api/v2/user", "GET", "Authorization", "fixture", `{"user":{"id":123}}`, "invalid"},
		{"fastly-api-token", "https://api.fastly.com/tokens/self", "GET", "Fastly-Key", "fixture", `{"id":"t1","scope":"global"}`, "revoked"},
		{"figma-personal-access-token", "https://api.figma.com/v1/me", "GET", "X-Figma-Token", "fixture", `{"id":"u1"}`, "invalid"},
		{"figma-personal-access-header-token", "https://api.figma.com/v1/me", "GET", "X-Figma-Token", "fixture", `{"id":"u1"}`, "invalid"},
		{"fullstory-api-key", "https://api.fullstory.com/me", "GET", "Authorization", "Basic fixture", `{"role":"admin"}`, "invalid"},
		{"honeycomb-api-key", "https://api.honeycomb.io/1/auth", "GET", "X-Honeycomb-Team", "fixture", `{"team":{"slug":"test"}}`, "invalid"},
		{"hunter-api-key.1", "https://api.hunter.io/v2/account", "GET", "X-API-KEY", "fixture", `{"data":{"email":"test@example.com"}}`, "invalid"},
		{"linear-api-key", "https://api.linear.app/graphql", "POST", "Authorization", "fixture", `{"data":{"viewer":{"id":"u1"}}}`, "invalid"},
		{"mailchimp-api-key", "https://fixture.api.mailchimp.com/3.0/", "GET", "Authorization", "Basic eDpmaXh0dXJl", `{"account_id":"a1"}`, "invalid"},
		{"miro-access-token", "https://api.miro.com/v1/oauth-token", "GET", "Authorization", "Bearer fixture", `{"user":{"id":"u1"}}`, "invalid"},
		{"replicate-api-token", "https://api.replicate.com/v1/account", "GET", "Authorization", "Bearer fixture", `{"username":"tester","type":"user"}`, "invalid"},
		{"sendinblue-api-token", "https://api.brevo.com/v3/account", "GET", "api-key", "fixture", `{"email":"test@example.com"}`, "invalid"},
		{"vercel-api-token", "https://api.vercel.com/v2/user", "GET", "Authorization", "Bearer fixture", `{"user":{"id":"u1"}}`, "invalid"},
		{"vercel-personal-access-token", "https://api.vercel.com/v2/user", "GET", "Authorization", "Bearer fixture", `{"user":{"id":"u1"}}`, "invalid"},
		{"wakatime-api-key.1", "https://api.wakatime.com/api/v1/users/current?api_key=fixture", "GET", "Accept", "application/json", `{"data":{"id":"u1"}}`, "invalid"},
		{"wakatime-api-key.2", "https://api.wakatime.com/api/v1/users/current?api_key=fixture", "GET", "Accept", "application/json", `{"data":{"id":"u1"}}`, "invalid"},
		{"openrouter-api-key", "https://openrouter.ai/api/v1/key", "GET", "Authorization", "Bearer fixture", `{"data":{"label":"test"}}`, "invalid"},
		{"sendgrid-api-token", "https://api.sendgrid.com/v3/scopes", "GET", "Authorization", "Bearer fixture", `{"scopes":["mail.send"]}`, "invalid"},
		{"twitch-api-token", "https://id.twitch.tv/oauth2/validate", "GET", "Authorization", "OAuth fixture", `{"client_id":"c1","scopes":["user:read:email"]}`, "invalid"},
		{"xai-api-key", "https://api.x.ai/v1/api-key", "GET", "Authorization", "Bearer fixture", `{"api_key_id":"k1","acls":["api-key:read"]}`, "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			for _, response := range []struct {
				name   string
				status int
				body   string
				want   report.ValidationStatus
			}{
				{"valid", 200, tc.body, "valid"},
				{"empty success", 200, `{}`, "unknown"},
				{"unauthorized", 401, `{}`, tc.unauthorized},
				{"rate limit", 429, `{}`, "unknown"},
				{"server error", 500, `{}`, "unknown"},
			} {
				t.Run(response.name, func(t *testing.T) {
					result, calls := evalRuleFixture(t, cfg, tc.id, "fixture", nil, response.status, response.body, func(r *http.Request) {
						require.Equal(t, tc.url, r.URL.String())
						require.Equal(t, tc.method, r.Method)
						require.Equal(t, tc.auth, r.Header.Get(tc.header))
					})
					require.Equal(t, 1, calls)
					require.Equal(t, response.want, result.Status, result.Reason)
					require.NotContains(t, result.Metadata, "analysis")
					require.NotContains(t, result.Metadata, "metadata")
				})
			}
		})
	}
}

func evalRuleFixture(t *testing.T, cfg *config.Config, id, secret string, components map[string]any, status int, body string, check func(*http.Request)) (*validate.Result, int) {
	t.Helper()
	calls := 0
	runtime, err := exprruntime.New(&http.Client{Transport: ruleFixtureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if check != nil {
			check(r)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})})
	require.NoError(t, err)
	runtime.AllowedEnv = exprruntime.ParseValidationEnvAllowlist([]string{"GITLAB_BASE_URL"})
	rule, ok := cfg.Rules[id]
	require.True(t, ok, "rule %s missing from default config", id)
	require.NotEmpty(t, rule.ValidateExpr)
	program, err := runtime.CompileValidation(rule.ValidateExpr)
	require.NoError(t, err)
	value, err := runtime.EvalValidationWithComponents(t.Context(), program, map[string]string{"secret": secret, "rule_id": id}, nil, components, nil, exprruntime.EvalOptions{})
	require.NoError(t, err)
	return validate.ParseResult(value.Value), calls
}

func TestBackportedProviderSpecificStatuses(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	tests := []struct {
		id     string
		status int
		body   string
		want   report.ValidationStatus
	}{
		{"nuget-api-key", 404, "Package does not exist.", "valid"},
		{"nuget-api-key", 404, "Not Found", "unknown"},
		{"nuget-api-key", 400, "Account policy", "valid"},
		{"nuget-api-key", 403, "Forbidden", "invalid"},
		{"nuget-api-key", 429, "", "unknown"},
		{"rubygems-api-token", 200, `[]`, "valid"},
		{"rubygems-api-token", 403, "API key lacks permission", "valid"},
		{"rubygems-api-token", 403, "Access Denied. You have provided an invalid API key.", "revoked"},
		{"rubygems-api-token", 401, "Unauthorized", "invalid"},
		{"rubygems-api-token", 500, "Server error", "unknown"},
		{"sendgrid-api-token", 200, `{"scopes":[123]}`, "unknown"},
		{"linear-api-key", 200, `{"data":{"viewer":{"id":"u1"}},"errors":[{"message":"denied"}]}`, "unknown"},
		{"xai-api-key", 200, `{"api_key_id":"k1","api_key_disabled":true}`, "invalid"},
		{"xai-api-key", 200, `{"api_key_id":"k1","api_key_blocked":true}`, "invalid"},
		{"xai-api-key", 200, `{"api_key_id":"k1","team_blocked":true}`, "invalid"},
		{"fullstory-api-key", 403, `{}`, "unknown"},
		{"miro-access-token", 400, `{}`, "invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.id+"/"+tc.body, func(t *testing.T) {
			result, calls := evalRuleFixture(t, cfg, tc.id, "fixture", nil, tc.status, tc.body, func(r *http.Request) {
				method := "GET"
				if tc.id == "linear-api-key" {
					method = "POST"
				}
				require.Equal(t, method, r.Method)
				if tc.id == "nuget-api-key" {
					require.Equal(t, "https://www.nuget.org/api/v2/verifykey/betterleaks--nonexistent/0.0.0", r.URL.String())
					require.Equal(t, "fixture", r.Header.Get("X-NuGet-ApiKey"))
				}
				if tc.id == "rubygems-api-token" {
					require.Equal(t, "https://rubygems.org/api/v1/gems.json", r.URL.String())
					require.Equal(t, "fixture", r.Header.Get("Authorization"))
				}
			})
			require.Equal(t, 1, calls)
			require.Equal(t, tc.want, result.Status, result.Reason)
		})
	}
}

func TestSlackValidationStatuses(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	for _, id := range []string{"slack-bot-token", "slack-user-token", "slack-legacy-bot-token"} {
		for _, tc := range []struct {
			body string
			want report.ValidationStatus
		}{
			{`{"ok":true,"team_id":"T1","user_id":"U1"}`, "valid"},
			{`{"ok":false,"error":"token_revoked"}`, "revoked"},
			{`{"ok":false,"error":"token_expired"}`, "revoked"},
			{`{"ok":false,"error":"account_inactive"}`, "revoked"},
			{`{"ok":false,"error":"invalid_auth"}`, "invalid"},
			{`{"ok":false,"error":"not_authed"}`, "invalid"},
			{`{"ok":false,"error":"ratelimited"}`, "unknown"},
			{`{}`, "unknown"},
		} {
			t.Run(id+"/"+tc.body, func(t *testing.T) {
				result, calls := evalRuleFixture(t, cfg, id, "fixture", nil, 200, tc.body, func(r *http.Request) {
					require.Equal(t, "POST", r.Method)
					require.Equal(t, "https://slack.com/api/auth.test", r.URL.String())
					require.Equal(t, "Bearer fixture", r.Header.Get("Authorization"))
					if r.Body != nil {
						body, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						require.Empty(t, body)
					}
				})
				require.Equal(t, 1, calls)
				require.Equal(t, tc.want, result.Status, result.Reason)
			})
		}
	}
}

func TestCloudflareValidationRoutes(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	const account = "11111111111111111111111111111111"
	for _, tc := range []struct {
		name, id, secret, path string
		components             map[string]any
		want                   report.ValidationStatus
	}{
		{"legacy", "cloudflare-api-key", "fixture", "/client/v4/user/tokens/verify", nil, "valid"},
		{"user", "cloudflare-api-key.2", "cfut_fixture", "/client/v4/user/tokens/verify", nil, "valid"},
		{"account", "cloudflare-api-key.2", "cfat_fixture", "/client/v4/accounts/" + account + "/tokens/verify", map[string]any{"cloudflare-account-id.1": map[string]any{"secret": account}}, "valid"},
		{"missing account", "cloudflare-api-key.2", "cfat_fixture", "", nil, "needs_validation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, calls := evalRuleFixture(t, cfg, tc.id, tc.secret, tc.components, 200, `{"success":true,"result":{"id":"t1","status":"active"}}`, func(r *http.Request) {
				require.Equal(t, "GET", r.Method)
				require.Equal(t, "api.cloudflare.com", r.URL.Host)
				require.Equal(t, tc.path, r.URL.Path)
				require.Equal(t, "Bearer "+tc.secret, r.Header.Get("Authorization"))
			})
			require.Equal(t, tc.want, result.Status, result.Reason)
			if tc.want == "needs_validation" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
				require.Equal(t, "t1", result.Metadata["token_id"])
			}
		})
	}
	for _, tc := range []struct {
		status int
		body   string
		want   report.ValidationStatus
	}{
		{200, `{"success":true,"result":{"status":"disabled"}}`, "revoked"},
		{200, `{"success":true,"result":{"status":"expired"}}`, "revoked"},
		{200, `{"success":false,"result":{"id":"t1","status":"active"}}`, "unknown"},
		{200, `{"success":true,"result":{"status":"active"}}`, "unknown"},
		{403, `{}`, "invalid"},
		{429, `{}`, "unknown"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			result, _ := evalRuleFixture(t, cfg, "cloudflare-api-key.2", "cfut_fixture", nil, tc.status, tc.body, nil)
			require.Equal(t, tc.want, result.Status, result.Reason)
		})
	}
}

func TestGitLabValidationBaseURL(t *testing.T) {
	t.Setenv("GITLAB_BASE_URL", "https://gitlab.example.com")
	cfg, err := config.Default()
	require.NoError(t, err)
	for _, id := range []string{"gitlab-pat", "gitlab-pat-routable", "gitlab-pat-routable-versioned"} {
		t.Run(id, func(t *testing.T) {
			result, _ := evalRuleFixture(t, cfg, id, "fixture", nil, 200, `{"name":"test"}`, func(r *http.Request) {
				require.Equal(t, "https://gitlab.example.com/api/v4/personal_access_tokens/self", r.URL.String())
				require.Equal(t, "fixture", r.Header.Get("PRIVATE-TOKEN"))
			})
			require.Equal(t, report.ValidationStatusValid, result.Status)
			require.Equal(t, "test", result.Metadata["name"])
		})
	}
}
