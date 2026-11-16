package rules

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	ruleID                           string
	url, authHeader, authValue, body string
	identity                         *report.AnalysisIdentity
	capabilities                     []report.Capability
}

// Ordered HTTP fixtures exercise the real validation -> analysis handoff. Every
// request is intercepted; an unexpected request fails instead of reaching a provider.
type enrichmentStep struct {
	method, url, body string
	headers           map[string]string
	status            int
	response          string
	check             func(*testing.T, *http.Request)
}

type enrichmentFixture struct {
	ruleID, secret string
	components     map[string]string
	steps          []enrichmentStep
	identity       *report.AnalysisIdentity
	capabilities   []report.Capability
	metadata       map[string]any
	allowedEnv     map[string]struct{}
	env            map[string]string
}

func enrichmentGET(endpoint, header, auth, response string) enrichmentStep {
	return enrichmentStep{method: "GET", url: endpoint, headers: map[string]string{header: auth}, status: 200, response: response}
}

func enrichmentFixtures() []enrichmentFixture {
	const secret = "enrichment-secret"
	const bearer = "Bearer " + secret
	fixtures := []enrichmentFixture{
		{ruleID: "mux-access-token-secret.1", components: map[string]string{"mux-access-token-id.1": "token-id"}, steps: []enrichmentStep{enrichmentGET("https://api.mux.com/system/v1/whoami", "Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("token-id:"+secret)), `{"data":{"organization_id":"org-1","organization_name":"Example","environment_id":"env-1","environment_name":"Development","environment_type":"development","access_token_name":"Build bot","permissions":["video:read","system:write"],"secret":"unexpected-secret"}}`)}, identity: &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "org-1", Name: "Example"}}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite}, metadata: map[string]any{"environment_id": "env-1", "token_name": "Build bot"}},
		{ruleID: "vultr-api-key.1", steps: []enrichmentStep{enrichmentGET("https://api.vultr.com/v2/account", "Authorization", bearer, `{"account":{"email":"alex@example.com","name":"Alex","acls":["subscriptions_view","dns","manage_users"],"api_key":"unexpected-secret"}}`)}, identity: &report.AnalysisIdentity{Name: "Alex", Email: "alex@example.com"}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityManageUsers}},
		{ruleID: "paypal-client-secret.1", components: map[string]string{"paypal-client-id.1": "client"}, steps: []enrichmentStep{{method: "POST", url: "https://api-m.paypal.com/v1/oauth2/token", headers: map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("client:"+secret)), "Content-Type": "application/x-www-form-urlencoded"}, body: "grant_type=client_credentials", status: 200, response: `{"access_token":"unexpected-secret","app_id":"APP-123","scope":"https://uri.paypal.com/services/payments/refund https://uri.paypal.com/services/disputes/read-seller","expires_in":300,"nonce":"unexpected-secret"}`}}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite}, metadata: map[string]any{"app_id": "APP-123"}},
		{ruleID: "square-access-token", steps: []enrichmentStep{{method: "POST", url: "https://connect.squareup.com/oauth2/token/status", headers: map[string]string{"Authorization": bearer, "Content-Type": "application/json"}, body: `{}`, status: 200, response: `{"merchant_id":"merchant-1","client_id":"app-1","scopes":["PAYMENTS_READ","PAYMENTS_WRITE"],"expires_at":"2027-01-01T00:00:00Z"}`}}, identity: &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "merchant-1"}}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite}, metadata: map[string]any{"expires_at": "2027-01-01T00:00:00Z"}},
		{ruleID: "sentry-access-token", steps: []enrichmentStep{enrichmentGET("https://sentry.io/api/0/", "Authorization", bearer, `{"auth":{"scopes":["project:read","member:write"],"token":"unexpected-secret"},"user":{"id":"42","username":"alex","name":"Alex","email":"alex@example.com"}}`)}, identity: &report.AnalysisIdentity{ID: "42", Username: "alex", Name: "Alex", Email: "alex@example.com"}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityManageUsers}},
		{ruleID: "lichess-personal-access-token", steps: []enrichmentStep{{method: "POST", url: "https://lichess.org/api/token/test", headers: map[string]string{"Content-Type": "text/plain"}, body: secret, status: 200, response: `{"enrichment-secret":{"userId":"alex","scopes":"study:read, study:write","expires":1800000000000,"token":"unexpected-secret"},"another-secret":{"userId":"wrong"}}`}}, identity: &report.AnalysisIdentity{ID: "alex"}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite}, metadata: map[string]any{"expires_at_ms": float64(1800000000000)}},
		{ruleID: "posthog-personal-api-key", steps: []enrichmentStep{enrichmentGET("https://us.posthog.com/api/personal_api_keys/@current/", "Authorization", bearer, `{"id":"key-1","user_id":42,"scopes":["project:write","organization_member:write"],"scoped_teams":[12],"scoped_organizations":["org-1"],"current_organization_id":"not-a-boundary","local_dev_value":"unexpected-secret","value":"unexpected-secret"}`)}, identity: &report.AnalysisIdentity{ID: "42"}, capabilities: []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityManageUsers}, metadata: map[string]any{"region": "us", "scoped_teams": []any{float64(12)}, "scoped_organizations": []any{"org-1"}}},
		{ruleID: "launchdarkly-access-token", steps: []enrichmentStep{
			enrichmentGET("https://app.launchdarkly.com/api/v2/caller-identity", "Authorization", secret, `{"accountId":"account-1","tokenId":"token-1","memberId":"member-1","serviceToken":false}`),
			enrichmentGET("https://app.launchdarkly.com/api/v2/tokens/token-1", "Authorization", secret, `{"_id":"token-1","token":"unexpected-secret","role":"reader","_member":{"_id":"member-1","email":"alex@example.com","role":"admin"},"inlineRole":[{"effect":"deny","actions":["*"],"resources":["proj/private:*"],"secret":"unexpected-secret"}]}`),
		}, identity: &report.AnalysisIdentity{ID: "member-1", Email: "alex@example.com", Account: &report.AnalysisAccount{ID: "account-1"}}, metadata: map[string]any{"role": "reader", "custom_roles_complete": true}},
		{ruleID: "anthropic-admin-api-key", steps: []enrichmentStep{enrichmentGET("https://api.anthropic.com/v1/organizations/me", "x-api-key", secret, `{"id":"org-1","type":"organization","name":"Acme","role":"admin"}`)}, identity: &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "org-1", Name: "Acme"}}},
		{ruleID: "cohere-api-token", steps: []enrichmentStep{{method: "POST", url: "https://api.cohere.com/v1/check-api-key", headers: map[string]string{"Authorization": bearer, "Content-Type": "application/json"}, body: `{}`, status: 200, response: `{"valid":true,"owner_id":"user-1","organization_id":"org-1"}`}}, identity: &report.AnalysisIdentity{ID: "user-1", Account: &report.AnalysisAccount{ID: "org-1"}}},
		{ruleID: "devin-service-user-token", steps: []enrichmentStep{enrichmentGET("https://api.devin.ai/v3/self", "Authorization", bearer, `{"principal_type":"service_user","service_user_id":"service-1","service_user_name":"Build bot","org_id":"org-1","role":"admin"}`)}, identity: &report.AnalysisIdentity{ID: "service-1", Name: "Build bot", Account: &report.AnalysisAccount{ID: "org-1"}}},
		{ruleID: "weights-and-biases-api-key", steps: []enrichmentStep{{method: "POST", url: "https://api.wandb.ai/graphql", headers: map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("api:"+secret)), "Content-Type": "application/json"}, body: `{"query":"query { viewer { id email username entity } }"}`, status: 200, response: `{"data":{"viewer":{"id":"user-1","username":"alex","email":"alex@example.com","entity":"default-team","apiKey":"unexpected-secret"}}}`}}, identity: &report.AnalysisIdentity{ID: "user-1", Username: "alex", Email: "alex@example.com"}, metadata: map[string]any{"entity": "default-team"}},
		{ruleID: "stripe-access-token", steps: []enrichmentStep{enrichmentGET("https://api.stripe.com/v1/account", "Authorization", bearer, `{"object":"account","id":"acct_1","business_profile":{"name":"Acme"},"capabilities":{"card_payments":"active","transfers":"active"}}`)}, identity: &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "acct_1", Name: "Acme"}}},
		{ruleID: "tableau-personal-access-token.1", components: map[string]string{"tableau-server-host.1": "prod.online.tableau.com", "tableau-personal-access-token-name.1": `build"bot`}, steps: []enrichmentStep{{method: "POST", url: "https://prod.online.tableau.com/api/3.26/auth/signin", headers: map[string]string{"Content-Type": "application/json", "Accept": "application/json"}, body: `{"credentials":{"personalAccessTokenName":"build\"bot","personalAccessTokenSecret":"enrichment-secret","site":{"contentUrl":"example"}}}`, status: 200, response: `{"credentials":{"token":"unexpected-secret","user":{"id":"user-1"},"site":{"id":"site-1","contentUrl":"example"}}}`}}, identity: &report.AnalysisIdentity{ID: "user-1", Account: &report.AnalysisAccount{ID: "site-1"}}, metadata: map[string]any{"site_content_url": "example"}, allowedEnv: map[string]struct{}{"TABLEAU_SITE_CONTENT_URL": {}}, env: map[string]string{"TABLEAU_SITE_CONTENT_URL": "example"}},
		{ruleID: "notion-api-token", steps: []enrichmentStep{enrichmentGET("https://api.notion.com/v1/users/me", "Authorization", bearer, `{"object":"user","type":"bot","id":"bot-1","name":"Build bot","bot":{"workspace_id":"ws-1","workspace_name":"Acme","owner":{"type":"user","user":{"id":"owner-1","person":{"email":"owner@example.com"}}}}}`)}, identity: &report.AnalysisIdentity{ID: "bot-1", Name: "Build bot", Account: &report.AnalysisAccount{ID: "ws-1", Name: "Acme"}}, metadata: map[string]any{"owner_id": "owner-1"}},
		{ruleID: "postman-api-token", steps: []enrichmentStep{enrichmentGET("https://api.getpostman.com/me", "X-Api-Key", secret, `{"user":{"id":42,"username":"alex","fullName":"Alex","email":"alex@example.com","role":"admin"}}`)}, identity: &report.AnalysisIdentity{ID: "42", Username: "alex", Name: "Alex", Email: "alex@example.com"}},
		{ruleID: "elevenlabs-api-key", steps: []enrichmentStep{enrichmentGET("https://api.elevenlabs.io/v1/user", "xi-api-key", secret, `{"user_id":"user-1","workspace_id":"ws-1","subscription":{"tier":"enterprise"},"is_new_user":false}`)}, identity: &report.AnalysisIdentity{ID: "user-1", Account: &report.AnalysisAccount{ID: "ws-1"}}},
	}
	for _, alias := range [][2]string{{"sentry-access-token", "sentry-org-token"}, {"sentry-access-token", "sentry-user-token"}, {"weights-and-biases-api-key", "weights-and-biases-api-key-v1"}} {
		for _, fixture := range fixtures {
			if fixture.ruleID == alias[0] {
				fixture.ruleID = alias[1]
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
				fixtures = append(fixtures, fixture)
				break
			}
		}
	}
	return fixtures
}

func runEnrichmentFixture(t *testing.T, fixture enrichmentFixture) (*provider.Result, report.Analysis) {
	t.Helper()
	for name, value := range fixture.env {
		t.Setenv(name, value)
	}
	calls := 0
	runtime, err := exprruntime.New(&http.Client{Transport: analysisFixtureTransport(func(req *http.Request) (*http.Response, error) {
		require.Less(t, calls, len(fixture.steps), "unexpected %s %s", req.Method, req.URL)
		step := fixture.steps[calls]
		calls++
		assert.Equal(t, step.method, req.Method)
		if step.url != "" {
			assert.Equal(t, step.url, req.URL.String())
		}
		for key, value := range step.headers {
			assert.Equal(t, value, req.Header.Get(key), key)
		}
		if step.check != nil {
			step.check(t, req)
		}
		if step.body != "" {
			raw, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			if strings.HasPrefix(step.body, "{") {
				assert.JSONEq(t, step.body, string(raw))
			} else {
				assert.Equal(t, step.body, string(raw))
			}
		}
		return &http.Response{StatusCode: step.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(step.response))}, nil
	})})
	require.NoError(t, err)
	runtime.AllowedEnv = fixture.allowedEnv
	rule := testRule(t, fixture.ruleID)
	program, err := runtime.CompileValidation(rule.ValidateExpr)
	require.NoError(t, err)
	secret := fixture.secret
	if secret == "" {
		secret = "enrichment-secret"
	}
	finding := map[string]string{"rule_id": fixture.ruleID, "secret": secret}
	components := map[string]any{}
	for key, value := range fixture.components {
		components[key] = map[string]any{"secret": value}
	}
	value, err := runtime.EvalValidationWithComponents(t.Context(), program, finding, nil, components, nil, exprruntime.EvalOptions{})
	require.NoError(t, err)
	result := provider.ParseResult(value.Value)
	var analysis report.Analysis
	if result.Status == report.ValidationStatusValid {
		program, err = runtime.CompileAnalysis(rule.AnalyzeExpr)
		require.NoError(t, err)
		value, err = runtime.EvalAnalysisWithComponents(t.Context(), program, finding, nil, components, nil, map[string]any{"analysis": result.Analysis, "metadata": result.Metadata, "status": string(result.Status)}, exprruntime.EvalOptions{})
		require.NoError(t, err)
		analysis, err = analysisresult.ParseResult(value.Value)
		require.NoError(t, err)
	}
	assert.Equal(t, len(fixture.steps), calls)
	output, err := json.Marshal([]any{result.Analysis, result.Metadata, analysis})
	require.NoError(t, err)
	assert.NotContains(t, string(output), "unexpected-secret")
	assert.NotContains(t, string(output), secret)
	return result, analysis
}

func TestEnrichmentProviderFixtures(t *testing.T) {
	for _, fixture := range enrichmentFixtures() {
		t.Run(fixture.ruleID, func(t *testing.T) {
			for i := range fixture.steps {
				var payload map[string]any
				require.NoError(t, json.Unmarshal([]byte(fixture.steps[i].response), &payload))
				payload["access_token"] = "unexpected-secret"
				payload["api_secret"] = "unexpected-secret"
				raw, err := json.Marshal(payload)
				require.NoError(t, err)
				fixture.steps[i].response = string(raw)
			}
			result, analysis := runEnrichmentFixture(t, fixture)
			assert.Equal(t, report.ValidationStatusValid, result.Status)
			assert.Equal(t, fixture.identity, analysis.Identity)
			assert.ElementsMatch(t, fixture.capabilities, analysis.Capabilities)
			assert.Equal(t, report.AnalysisSeverity(fixture.capabilities), analysis.Severity)
			switch fixture.ruleID {
			case "mux-access-token-secret.1", "anthropic-admin-api-key", "weights-and-biases-api-key", "weights-and-biases-api-key-v1":
				assert.Empty(t, result.Metadata, "identity must not be duplicated in status_metadata")
			}
			for key, value := range fixture.metadata {
				assert.Equal(t, value, analysis.Metadata[key], key)
			}
		})
	}
}

func TestEnrichmentRejectsUnprovenAuthentication(t *testing.T) {
	for _, fixture := range enrichmentFixtures() {
		for _, test := range []struct {
			status int
			body   string
		}{{401, `{}`}, {403, `{}`}, {429, `{}`}, {500, `{}`}, {200, `{}`}, {200, `null`}, {200, `[]`}, {200, `"unexpected-secret"`}, {200, `<html>sign in</html>`}} {
			t.Run(fmt.Sprintf("%s/%d/%s", fixture.ruleID, test.status, test.body), func(t *testing.T) {
				fixture.steps = append([]enrichmentStep(nil), fixture.steps[:1]...)
				fixture.steps[0].status, fixture.steps[0].response = test.status, test.body
				if fixture.ruleID == "posthog-personal-api-key" {
					eu := fixture.steps[0]
					eu.url = strings.Replace(eu.url, "us.posthog.com", "eu.posthog.com", 1)
					fixture.steps = append(fixture.steps, eu)
				}
				want := report.ValidationStatusUnknown
				if test.status == 401 && fixture.ruleID != "paypal-client-secret.1" && fixture.ruleID != "square-access-token" && fixture.ruleID != "tableau-personal-access-token.1" && fixture.ruleID != "lichess-personal-access-token" && fixture.ruleID != "elevenlabs-api-key" {
					want = report.ValidationStatusInvalid
				}
				result, _ := runEnrichmentFixture(t, fixture)
				assert.Equal(t, want, result.Status)
				assert.Empty(t, result.Analysis)
			})
		}
	}
}

func TestEnrichmentCloudIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	credential, err := json.Marshal(map[string]string{"type": "service_account", "project_id": "declared-project", "client_email": "bot@example.iam.gserviceaccount.com", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": "https://oauth2.googleapis.com/token"})
	require.NoError(t, err)
	fixtures := []enrichmentFixture{
		{ruleID: "gcp-service-account", secret: string(credential), steps: []enrichmentStep{{method: "POST", url: "https://oauth2.googleapis.com/token", status: 200, response: `{"access_token":"unexpected-secret"}`, check: func(t *testing.T, r *http.Request) {
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.Form.Get("grant_type"))
			assert.Len(t, strings.Split(r.Form.Get("assertion"), "."), 3)
		}}}, identity: &report.AnalysisIdentity{Email: "bot@example.iam.gserviceaccount.com"}, metadata: map[string]any{"declared_project_id": "declared-project"}},
		{ruleID: "azure-ad-client-secret", components: map[string]string{"azure-client-id": "client-1", "azure-tenant-id": "tenant-1"}, steps: []enrichmentStep{{method: "POST", url: "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token", status: 200, response: `{"access_token":"unexpected-secret"}`, check: func(t *testing.T, r *http.Request) {
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "client-1", r.Form.Get("client_id"))
			assert.Equal(t, "enrichment-secret", r.Form.Get("client_secret"))
			assert.Equal(t, "https://management.azure.com/.default", r.Form.Get("scope"))
		}}}, identity: &report.AnalysisIdentity{ID: "client-1", Account: &report.AnalysisAccount{ID: "tenant-1"}}},
		{ruleID: "azure-storage-account-key", secret: base64.StdEncoding.EncodeToString([]byte("fixture-storage-key")), components: map[string]string{"azure-storage-account-name": "fixturestorage"}, steps: []enrichmentStep{{method: "GET", url: "https://fixturestorage.blob.core.windows.net/?comp=list", status: 200, response: `<EnumerationResults><Containers/></EnumerationResults>`, check: func(t *testing.T, r *http.Request) {
			assert.True(t, strings.HasPrefix(r.Header.Get("Authorization"), "SharedKey fixturestorage:"))
		}}}, identity: &report.AnalysisIdentity{Account: &report.AnalysisAccount{Name: "fixturestorage"}}, capabilities: []report.Capability{report.CapabilityRead}},
	}
	for _, ruleID := range []string{"alibaba-secret-key", "alibaba-sts-access-key-secret"} {
		components := map[string]string{"alibaba-access-key-id": "access-id"}
		if ruleID == "alibaba-sts-access-key-secret" {
			components = map[string]string{"alibaba-sts-access-key-id": "access-id", "alibaba-sts-security-token": "sts-token"}
		}
		fixtures = append(fixtures, enrichmentFixture{ruleID: ruleID, components: components, steps: []enrichmentStep{{method: "GET", status: 200, response: `{"AccountId":"account-1","PrincipalId":"principal-1","Arn":"acs:ram::account-1:user/alex","IdentityType":"RAMUser","AccessKeySecret":"unexpected-secret"}`, check: func(t *testing.T, r *http.Request) {
			assert.Equal(t, "sts.aliyuncs.com", r.URL.Host)
			query := r.URL.Query()
			assert.Equal(t, "GetCallerIdentity", query.Get("Action"))
			assert.Equal(t, "access-id", query.Get("AccessKeyId"))
			if ruleID == "alibaba-sts-access-key-secret" {
				assert.Equal(t, "sts-token", query.Get("SecurityToken"))
			} else {
				assert.Empty(t, query.Get("SecurityToken"))
			}
			signature := query.Get("Signature")
			query.Del("Signature")
			escape := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
			mac := hmac.New(sha1.New, []byte("enrichment-secret&"))
			_, err := mac.Write([]byte("GET&%2F&" + escape(query.Encode())))
			require.NoError(t, err)
			assert.Equal(t, base64.StdEncoding.EncodeToString(mac.Sum(nil)), signature, "sign the sorted provider parameters")
		}}}, identity: &report.AnalysisIdentity{ID: "principal-1", Account: &report.AnalysisAccount{ID: "account-1"}}, metadata: map[string]any{"identity_type": "RAMUser"}})
	}
	for _, fixture := range fixtures {
		t.Run(fixture.ruleID, func(t *testing.T) {
			result, analysis := runEnrichmentFixture(t, fixture)
			assert.Equal(t, report.ValidationStatusValid, result.Status)
			assert.Equal(t, fixture.identity, analysis.Identity)
			assert.ElementsMatch(t, fixture.capabilities, analysis.Capabilities)
			switch fixture.ruleID {
			case "gcp-service-account", "azure-ad-client-secret":
				assert.Empty(t, result.Metadata, "identity and analysis evidence must not be duplicated in status_metadata")
			case "azure-storage-account-key":
				assert.NotContains(t, result.Metadata, "account")
				assert.Contains(t, result.Metadata, "containers", "preserve distinct validation evidence")
			}
			for key, value := range fixture.metadata {
				assert.Equal(t, value, analysis.Metadata[key])
			}
			for _, status := range []int{403, 404, 429, 500} {
				t.Run(fmt.Sprint(status), func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
					fixture.steps[0].status = status
					fixture.steps[0].response = `{}`
					result, _ := runEnrichmentFixture(t, fixture)
					assert.Equal(t, report.ValidationStatusUnknown, result.Status)
					assert.Empty(t, result.Analysis)
				})
			}
			for _, body := range []string{`{}`, `null`, `[]`, `<html>sign in</html>`, `{"access_token":""}`, `{"access_token":42}`} {
				t.Run(body, func(t *testing.T) {
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
					fixture.steps[0].response = body
					result, _ := runEnrichmentFixture(t, fixture)
					assert.Equal(t, report.ValidationStatusUnknown, result.Status)
					assert.Empty(t, result.Analysis)
				})
			}
		})
	}
}

func TestEnrichmentPermissionBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, expr string
		input      map[string]any
		want       []report.Capability
	}{
		{"Vultr unknown ACLs", vultrAnalyzeExpr, map[string]any{"acls": []any{"admin", "future_write", "api"}}, nil},
		{"Vultr users only", vultrAnalyzeExpr, map[string]any{"acls": []any{"manage_users"}}, []report.Capability{report.CapabilityManageUsers}},
		{"PayPal identity scopes", paypalAnalyzeExpr, map[string]any{"scopes": []any{"openid", "https://uri.paypal.com/services/applications/webhooks", "future:write"}}, nil},
		{"Square future suffixes", squareAnalyzeExpr, map[string]any{"scopes": []any{"FUTURE_READ", "FUTURE_WRITE", "ADMIN"}}, nil},
		{"Square payments only", squareAnalyzeExpr, map[string]any{"scopes": []any{"PAYMENTS_WRITE"}}, []report.Capability{report.CapabilityWrite}},
		{"Sentry scoped admin", sentryAnalyzeExpr, map[string]any{"scopes": []any{"project:admin"}}, []report.Capability{report.CapabilityWrite}},
		{"Sentry CI uploads", sentryAnalyzeExpr, map[string]any{"scopes": []any{"org:ci"}}, []report.Capability{report.CapabilityWrite}},
		{"Sentry future scopes", sentryAnalyzeExpr, map[string]any{"scopes": []any{"future:read", "future:admin"}}, nil},
		{"Lichess empty scopes", lichessAnalyzeExpr, map[string]any{"scopes": []any{}}, nil},
		{"Lichess moderator is bounded by user rights", lichessAnalyzeExpr, map[string]any{"scopes": []any{"web:mod", "future:write"}}, nil},
		{"PostHog user profile only", posthogPersonalAnalyzeExpr, map[string]any{"scopes": []any{"user:read"}}, nil},
		{"PostHog future and wildcard grants", posthogPersonalAnalyzeExpr, map[string]any{"scopes": []any{"*", "future:write"}}, nil},
		{"PostHog write includes read", posthogPersonalAnalyzeExpr, map[string]any{"scopes": []any{"feature_flag:write"}}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := evaluateProviderAnalysis(t, test.expr, test.input)
			assert.ElementsMatch(t, test.want, result.Capabilities)
			assert.Equal(t, report.AnalysisSeverity(test.want), result.Severity)
		})
	}
}

func TestEnrichmentPartialAndProviderSpecificResponses(t *testing.T) {
	for _, fixture := range enrichmentFixtures() {
		switch fixture.ruleID {
		case "mux-access-token-secret.1":
			for _, test := range []struct {
				name, permissions string
				want              report.ValidationStatus
				caps              []report.Capability
			}{
				{"no permissions", `[]`, report.ValidationStatusValid, nil},
				{"unknown permission", `["future:admin"]`, report.ValidationStatusValid, nil},
				{"data only", `["data:read"]`, report.ValidationStatusValid, []report.Capability{report.CapabilityRead}},
				{"robots", `["robots:read","robots:write"]`, report.ValidationStatusValid, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
				{"system write", `["system:write"]`, report.ValidationStatusValid, []report.Capability{report.CapabilityWrite}},
				{"wrong permission type", `"video:read"`, report.ValidationStatusUnknown, nil},
				{"mixed permission types", `["video:read",42]`, report.ValidationStatusUnknown, nil},
			} {
				t.Run("Mux/"+test.name, func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
					fixture.steps[0].response = `{"data":{"organization_id":"org-1","environment_id":"env-1","permissions":` + test.permissions + `}}`
					result, analysis := runEnrichmentFixture(t, fixture)
					assert.Equal(t, test.want, result.Status)
					assert.ElementsMatch(t, test.caps, analysis.Capabilities)
					assert.Empty(t, result.Metadata)
					if test.want == report.ValidationStatusValid {
						assert.Equal(t, &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "org-1"}}, analysis.Identity)
						assert.Equal(t, "env-1", analysis.Metadata["environment_id"])
						if test.name == "unknown permission" {
							assert.Equal(t, []any{"future:admin"}, analysis.Metadata["permissions"])
						}
					}
				})
			}
		case "tableau-personal-access-token.1":
			for _, allow := range []bool{false, true} {
				t.Run(fmt.Sprintf("Tableau missing site/allowlisted=%t", allow), func(t *testing.T) {
					fixture := fixture
					fixture.steps = nil
					if allow {
						fixture.env = map[string]string{"TABLEAU_SITE_CONTENT_URL": ""}
					} else {
						fixture.allowedEnv = nil
					}
					result, analysis := runEnrichmentFixture(t, fixture)
					assert.Equal(t, report.ValidationStatusNeedsValidation, result.Status)
					assert.Nil(t, analysis.Identity)
					assert.Contains(t, result.Reason, "TABLEAU_SITE_CONTENT_URL")
				})
			}
			t.Run("Tableau missing optional identity", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
				fixture.steps[0].response = `{"credentials":{"token":"unexpected-secret"}}`
				result, analysis := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusValid, result.Status)
				assert.Nil(t, analysis.Identity)
			})
		case "sentry-access-token":
			for _, body := range []string{`{"auth":null,"user":null}`, `{"auth":{"scopes":"project:read"}}`, `{"auth":{"scopes":["project:read",42]}}`} {
				t.Run("Sentry anonymous or malformed "+body, func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

					fixture.steps[0].response = body
					result, _ := runEnrichmentFixture(t, fixture)
					assert.Equal(t, report.ValidationStatusUnknown, result.Status)
				})
			}
			t.Run("Sentry organization token without user", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

				fixture.steps[0].response = `{"auth":{"scopes":["org:ci"]},"user":null}`
				result, analysis := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusValid, result.Status)
				assert.Nil(t, analysis.Identity)
				assert.Equal(t, []report.Capability{report.CapabilityWrite}, analysis.Capabilities)
			})
			t.Run("Sentry empty scopes", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

				fixture.steps[0].response = `{"auth":{"scopes":[]},"user":{"id":42}}`
				_, analysis := runEnrichmentFixture(t, fixture)
				assert.Equal(t, &report.AnalysisIdentity{ID: "42"}, analysis.Identity)
				assert.Empty(t, analysis.Capabilities)
			})
			t.Run("Sentry explicit regional URL", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

				t.Setenv("SENTRY_BASE_URL", "https://de.sentry.io/")
				fixture.allowedEnv = map[string]struct{}{"SENTRY_BASE_URL": {}}
				fixture.steps[0].url = "https://de.sentry.io/api/0/"
				result, _ := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusValid, result.Status)
			})
		case "lichess-personal-access-token":
			for _, test := range []struct {
				body string
				want report.ValidationStatus
			}{
				{`{"enrichment-secret":null}`, report.ValidationStatusInvalid},
				{`{"another-secret":{"userId":"wrong","scopes":"study:write"}}`, report.ValidationStatusUnknown},
				{`{"enrichment-secret":{"userId":"alex","scopes":"","expires":null}}`, report.ValidationStatusValid},
			} {
				t.Run("Lichess "+test.body, func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
					fixture.steps[0].response = test.body
					result, analysis := runEnrichmentFixture(t, fixture)
					assert.Equal(t, test.want, result.Status)
					assert.Empty(t, analysis.Capabilities)
				})
			}
		case "elevenlabs-api-key":
			for _, test := range []struct {
				code string
				want report.ValidationStatus
			}{{"invalid_api_key", report.ValidationStatusInvalid}, {"missing_permissions", report.ValidationStatusUnknown}} {
				t.Run("ElevenLabs "+test.code, func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
					fixture.steps[0].status = 401
					fixture.steps[0].response = `{"detail":{"status":"` + test.code + `"}}`
					result, _ := runEnrichmentFixture(t, fixture)
					assert.Equal(t, test.want, result.Status)
				})
			}
		case "weights-and-biases-api-key", "weights-and-biases-api-key-v1":
			// Sanitized shape from user-provided live output. Null profile fields
			// do not invalidate the principal or establish a service-account role.
			for _, profile := range []string{`,"email":null,"username":null`, ""} {
				t.Run(fixture.ruleID+"/nullable profile"+profile, func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
					fixture.steps[0].response = `{"data":{"viewer":{"id":"VXNlcjoxMjM0NQ==","entity":"example-team"` + profile + `}}}`
					result, analysis := runEnrichmentFixture(t, fixture)
					assert.Equal(t, report.ValidationStatusValid, result.Status)
					assert.Equal(t, &report.AnalysisIdentity{ID: "VXNlcjoxMjM0NQ=="}, analysis.Identity)
					assert.Equal(t, map[string]any{"entity": "example-team"}, analysis.Metadata)
					assert.Empty(t, analysis.Capabilities)
					assert.Equal(t, report.SeverityUnknown, analysis.Severity)
				})
			}
			t.Run(fixture.ruleID+"/partial GraphQL failure", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
				fixture.steps[0].response = `{"data":{"viewer":{"id":"user-1"}},"errors":[{"message":"denied"}]}`
				result, _ := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusUnknown, result.Status)
			})
		case "cohere-api-token":
			t.Run("Cohere invalid flag", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
				fixture.steps[0].response = `{"valid":false,"owner_id":"user-1"}`
				result, _ := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusInvalid, result.Status)
			})
			t.Run("Cohere missing optional owner", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
				fixture.steps[0].response = `{"valid":true}`
				result, analysis := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusValid, result.Status)
				assert.Nil(t, analysis.Identity)
				assert.Empty(t, analysis.Capabilities)
			})
		case "posthog-personal-api-key":
			for _, first := range []int{401, 403, 429, 500, 200} {
				t.Run(fmt.Sprintf("PostHog EU after US %d", first), func(t *testing.T) {
					fixture := fixture
					fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

					eu := fixture.steps[0]
					eu.url = strings.Replace(eu.url, "us.posthog.com", "eu.posthog.com", 1)
					us := fixture.steps[0]
					us.status = first
					us.response = `{"id":{},"user_id":42}`
					fixture.steps = []enrichmentStep{us, eu}
					result, analysis := runEnrichmentFixture(t, fixture)
					assert.Equal(t, report.ValidationStatusValid, result.Status)
					assert.Equal(t, "eu", analysis.Metadata["region"])
					assert.Nil(t, analysis.Identity.Account)
				})
			}
			t.Run("PostHog outage and rejected EU stays unknown", func(t *testing.T) {
				fixture := fixture
				fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

				us := fixture.steps[0]
				us.status = 500
				us.response = `{}`
				eu := us
				eu.url = strings.Replace(eu.url, "us.posthog.com", "eu.posthog.com", 1)
				eu.status = 401
				fixture.steps = []enrichmentStep{us, eu}
				result, _ := runEnrichmentFixture(t, fixture)
				assert.Equal(t, report.ValidationStatusUnknown, result.Status)
			})
		}
	}
}

func TestEnrichmentLaunchDarklyRequestBudget(t *testing.T) {
	var fixture enrichmentFixture
	for _, candidate := range enrichmentFixtures() {
		if candidate.ruleID == "launchdarkly-access-token" {
			fixture = candidate
			break
		}
	}
	for _, count := range []int{0, 1, 5, 8} {
		t.Run(fmt.Sprintf("%d custom roles", count), func(t *testing.T) {
			fixture := fixture
			fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

			ids := make([]string, count)
			for i := range count {
				ids[i] = fmt.Sprintf("role-%d", i)
			}
			body, err := json.Marshal(map[string]any{"_id": "token-1", "customRoleIds": ids, "token": "unexpected-secret"})
			require.NoError(t, err)
			fixture.steps[1].response = string(body)
			for _, id := range ids[:min(count, 5)] {
				fixture.steps = append(fixture.steps, enrichmentGET("https://app.launchdarkly.com/api/v2/roles/"+id, "Authorization", "enrichment-secret", `{"_id":"`+id+`","key":"friendly-`+id+`","policy":[{"effect":"allow","actions":["*"],"resources":["*"],"notResources":["proj/private:*"],"token":"unexpected-secret"},{"effect":"deny","actions":["deleteFlag"],"resources":["*"],"notActions":["readFlag"]}]}`))
			}
			result, analysis := runEnrichmentFixture(t, fixture)
			assert.Equal(t, report.ValidationStatusValid, result.Status)
			assert.Empty(t, analysis.Capabilities, "custom policies alone do not establish effective permissions")
			assert.Equal(t, count <= 5, analysis.Metadata["custom_roles_complete"])
			if count == 0 {
				assert.NotContains(t, analysis.Metadata, "custom_roles")
			} else {
				assert.Len(t, analysis.Metadata["custom_roles"], min(count, 5))
			}
			assert.LessOrEqual(t, len(fixture.steps)-1, 6)
			encoded, err := json.Marshal(analysis.Metadata)
			require.NoError(t, err)
			if count > 0 {
				assert.Contains(t, string(encoded), "notResources")
				assert.Contains(t, string(encoded), "deleteFlag")
			}
		})
	}
	for _, status := range []int{401, 403, 429, 500} {
		t.Run(fmt.Sprintf("token details unavailable %d", status), func(t *testing.T) {
			fixture := fixture
			fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

			fixture.steps[1].status = status
			fixture.steps[1].response = `{}`
			result, analysis := runEnrichmentFixture(t, fixture)
			assert.Equal(t, report.ValidationStatusValid, result.Status)
			assert.Equal(t, &report.AnalysisIdentity{ID: "member-1", Account: &report.AnalysisAccount{ID: "account-1"}}, analysis.Identity)
			assert.Equal(t, false, analysis.Metadata["token_details_retrieved"])
			assert.Empty(t, analysis.Capabilities)
		})
	}
	for _, test := range []struct{ name, caller, details, identityID string }{
		{"service token is not its creator", `{"accountId":"account-1","tokenId":"token-1","memberId":"creator-1","serviceToken":true}`, `{"_id":"token-1","_member":{"_id":"creator-1","email":"creator@example.com"}}`, ""},
		{"mismatched member", `{"accountId":"account-1","tokenId":"token-1","memberId":"member-1","serviceToken":false}`, `{"_id":"token-1","_member":{"_id":"wrong","email":"wrong@example.com"}}`, "member-1"},
		{"unsafe custom role identifier", `{"accountId":"account-1","tokenId":"token-1","serviceToken":true}`, `{"_id":"token-1","customRoleIds":["../other"]}`, ""},
		{"missing token kind does not establish human owner", `{"accountId":"account-1","tokenId":"token-1","memberId":"creator-1"}`, `{"_id":"token-1","_member":{"_id":"creator-1","email":"creator@example.com"}}`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := fixture
			fixture.steps = append([]enrichmentStep(nil), fixture.steps...)

			fixture.steps[0].response = test.caller
			fixture.steps[1].status = 200
			fixture.steps[1].response = test.details
			_, analysis := runEnrichmentFixture(t, fixture)
			assert.Equal(t, &report.AnalysisIdentity{ID: test.identityID, Account: &report.AnalysisAccount{ID: "account-1"}}, analysis.Identity)
			assert.Empty(t, analysis.Capabilities)
		})
	}
	for _, response := range []string{`{}`, `{"key":"wrong-role","policy":[]}`, `{"key":"role-1","policy":null}`} {
		t.Run("missing role evidence "+response, func(t *testing.T) {
			fixture := fixture
			fixture.steps = append([]enrichmentStep(nil), fixture.steps...)
			fixture.steps[1].response = `{"_id":"token-1","customRoleIds":["role-1"]}`
			fixture.steps = append(fixture.steps, enrichmentGET("https://app.launchdarkly.com/api/v2/roles/role-1", "Authorization", "enrichment-secret", response))
			if response == `{}` {
				fixture.steps[2].status = 403
			}
			result, analysis := runEnrichmentFixture(t, fixture)
			assert.Equal(t, report.ValidationStatusValid, result.Status)
			assert.Equal(t, false, analysis.Metadata["custom_roles_complete"])
			assert.Equal(t, "account-1", analysis.Identity.Account.ID)
			assert.Empty(t, analysis.Capabilities)
		})
	}
}

// These are synthetic responses based on the provider references in each rule,
// not captures from live credentials. Extra secret fields exercise allowlisting.
func analysisTargetFixtures() []targetFixture {
	return []targetFixture{
		{"apify-api-token", "https://api.apify.com/v2/users/me", "Authorization", "Bearer fixture-secret-us20", `{"data":{"id":"apify-user","username":"alex","email":"alex@example.com","proxy":{"password":"unexpected-secret"}}}`, &report.AnalysisIdentity{ID: "apify-user", Username: "alex", Email: "alex@example.com"}, nil},
		{"bitly-access-token", "https://api-ssl.bitly.com/v4/user", "Authorization", "Bearer fixture-secret-us20", `{"login":"alex","name":"Alex","emails":[{"email":"other@example.com","is_primary":false},{"email":"alex@example.com","is_primary":true}],"default_group_guid":"group-1"}`, &report.AnalysisIdentity{Username: "alex", Name: "Alex", Email: "alex@example.com"}, nil},
		{"box-api-access-token", "https://api.box.com/2.0/users/me", "Authorization", "Bearer fixture-secret-us20", `{"id":"box-user","name":"Alex","login":"alex@example.com","role":"admin"}`, &report.AnalysisIdentity{ID: "box-user", Name: "Alex", Email: "alex@example.com"}, nil},
		{"circleci-personal-token", "https://circleci.com/api/v2/me", "Circle-Token", "fixture-secret-us20", `{"id":"circle-user","login":"alex","name":"Alex"}`, &report.AnalysisIdentity{ID: "circle-user", Username: "alex", Name: "Alex"}, nil},
		{"clickup-personal-api-token", "https://api.clickup.com/api/v2/user", "Authorization", "fixture-secret-us20", `{"user":{"id":12345,"username":"alex","email":"alex@example.com"}}`, &report.AnalysisIdentity{ID: "12345", Username: "alex", Email: "alex@example.com"}, nil},
		{"figma-personal-access-token", "https://api.figma.com/v1/me", "X-Figma-Token", "fixture-secret-us20", `{"id":"figma-user","handle":"alex","email":"alex@example.com"}`, &report.AnalysisIdentity{ID: "figma-user", Username: "alex", Email: "alex@example.com"}, nil},
		{"figma-personal-access-header-token", "https://api.figma.com/v1/me", "X-Figma-Token", "fixture-secret-us20", `{"id":"figma-user","handle":"alex","email":"alex@example.com"}`, &report.AnalysisIdentity{ID: "figma-user", Username: "alex", Email: "alex@example.com"}, nil},
		{"labelbox-api-key", "https://api.labelbox.com/graphql", "Authorization", "Bearer fixture-secret-us20", `{"data":{"user":{"id":"lbx-user","email":"alex@example.com","organization":{"id":"lbx-org","name":"Acme"}}}}`, &report.AnalysisIdentity{ID: "lbx-user", Email: "alex@example.com", Account: &report.AnalysisAccount{ID: "lbx-org", Name: "Acme"}}, nil},
		{"linear-api-key", "https://api.linear.app/graphql", "Authorization", "fixture-secret-us20", `{"data":{"viewer":{"id":"linear-user","name":"Alex","email":"alex@example.com"}}}`, &report.AnalysisIdentity{ID: "linear-user", Name: "Alex", Email: "alex@example.com"}, nil},
		{"replicate-api-token", "https://api.replicate.com/v1/account", "Authorization", "Bearer fixture-secret-us20", `{"type":"organization","username":"acme","name":"Acme"}`, &report.AnalysisIdentity{Account: &report.AnalysisAccount{ID: "acme", Name: "Acme"}}, nil},
		{"mailchimp-api-key", "https://us20.api.mailchimp.com/3.0/", "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("x:fixture-secret-us20")), `{"account_id":"mc-account","account_name":"Acme","username":"alex","email":"alex@example.com","role":"owner"}`, &report.AnalysisIdentity{Username: "alex", Email: "alex@example.com", Account: &report.AnalysisAccount{ID: "mc-account", Name: "Acme"}}, nil},
		{"sendinblue-api-token", "https://api.brevo.com/v3/account", "api-key", "fixture-secret-us20", `{"organization_id":"brevo-org","user_id":42,"companyName":"Acme","email":"alex@example.com","firstName":"Alex","lastName":"Smith","marketingAutomation":{"key":"unexpected-secret"},"plan":[{"type":"paid","credits":10000}]}`, &report.AnalysisIdentity{ID: "42", Name: "Alex Smith", Email: "alex@example.com", Account: &report.AnalysisAccount{ID: "brevo-org", Name: "Acme"}}, nil},
		{"hunter-api-key.1", "https://api.hunter.io/v2/account", "X-API-KEY", "fixture-secret-us20", `{"data":{"email":"alex@example.com","first_name":"Alex","last_name":"Smith","plan_name":"Starter"}}`, &report.AnalysisIdentity{Name: "Alex Smith", Email: "alex@example.com"}, nil},
		{"wakatime-api-key.1", "https://api.wakatime.com/api/v1/users/current?api_key=fixture-secret-us20", "", "", `{"data":{"id":"waka-user","username":"alex","display_name":"Alex","email":"alex@example.com"}}`, &report.AnalysisIdentity{ID: "waka-user", Username: "alex", Name: "Alex", Email: "alex@example.com"}, nil},
		{"wakatime-api-key.2", "https://api.wakatime.com/api/v1/users/current?api_key=fixture-secret-us20", "", "", `{"data":{"id":"waka-user","username":"alex","display_name":"Alex","email":"alex@example.com"}}`, &report.AnalysisIdentity{ID: "waka-user", Username: "alex", Name: "Alex", Email: "alex@example.com"}, nil},
		{"miro-access-token", "https://api.miro.com/v1/oauth-token", "Authorization", "Bearer fixture-secret-us20", `{"type":"access-token","user":{"id":"miro-user","name":"Alex"},"team":{"id":"miro-team","name":"Team"},"organization":{"id":"miro-org","name":"Acme"},"scopes":["boards:read","boards:write"]}`, &report.AnalysisIdentity{ID: "miro-user", Name: "Alex", Account: &report.AnalysisAccount{ID: "miro-org", Name: "Acme"}}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
		{"sendgrid-api-token", "https://api.sendgrid.com/v3/scopes", "Authorization", "Bearer fixture-secret-us20", `{"scopes":["mail.send","api_keys.read","api_keys.create","teammates.update"]}`, nil, []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityCreateCredentials, report.CapabilityManageUsers}},
		{"twitch-api-token", "https://id.twitch.tv/oauth2/validate", "Authorization", "OAuth fixture-secret-us20", `{"client_id":"twitch-client","user_id":"twitch-user","login":"alex","scopes":["user:read:chat","user:write:chat"],"expires_in":300}`, &report.AnalysisIdentity{ID: "twitch-user", Username: "alex"}, []report.Capability{report.CapabilityRead, report.CapabilityWrite}},
		{"xai-api-key", "https://api.x.ai/v1/api-key", "Authorization", "Bearer fixture-secret-us20", `{"api_key_id":"xai-key","user_id":"xai-user","team_id":"xai-team","name":"Automation","acls":["api-key:endpoint:*","api-key:model:*"],"api_key_disabled":false,"api_key_blocked":false,"team_blocked":false,"redacted_api_key":"unexpected-secret"}`, &report.AnalysisIdentity{ID: "xai-user", Account: &report.AnalysisAccount{ID: "xai-team"}}, nil},
		{"openrouter-api-key", "https://openrouter.ai/api/v1/key", "Authorization", "Bearer fixture-secret-us20", `{"data":{"label":"unexpected-secret","creator_user_id":"or-user","organization_id":"or-org","workspace_id":"workspace","is_management_key":true,"limit":0,"limit_remaining":0,"usage":0}}`, &report.AnalysisIdentity{ID: "or-user", Account: &report.AnalysisAccount{ID: "or-org"}}, []report.Capability{report.CapabilityCreateCredentials}},
		{"fullstory-api-key", "https://api.fullstory.com/me", "Authorization", "Basic fixture-secret-us20", `{"role":"ADMIN"}`, nil, []report.Capability{report.CapabilityRead, report.CapabilityWrite, report.CapabilityAdmin}},
	}
}

func TestAnalysisTargetsProviderFixtures(t *testing.T) {
	for _, fixture := range analysisTargetFixtures() {
		rule := testRule(t, fixture.ruleID)
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
		graphQLQueries := map[string]string{
			"labelbox-api-key": `{"query":"query { user { id email organization { id name } } }"}`,
			"linear-api-key":   `{"query":"query { viewer { id name email } }"}`,
		}
		if query, ok := graphQLQueries[rule.ID]; ok {
			assert.Equal(t, http.MethodPost, req.Method)
			raw, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			assert.JSONEq(t, query, string(raw))
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
		rule := testRule(t, fixture.ruleID)
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
		})
	}
}

func TestAnalysisTargetsOptionalAndPartialResponses(t *testing.T) {
	fixtures := analysisTargetFixtures()
	for _, fixture := range fixtures {
		rule := testRule(t, fixture.ruleID)
		switch rule.ID {
		case "bitly-access-token":
			for _, body := range []string{`{"login":"alex"}`, `{"login":"alex","emails":null}`, `{"login":"alex","emails":[{"email":"wrong@example.com","is_primary":false}]}`} {
				_, analysis := runTargetFixture(t, rule, fixture, 200, body, true)
				require.NotNil(t, analysis.Identity)
				assert.Empty(t, analysis.Identity.Email)
				assert.Nil(t, analysis.Identity.Account)
			}
		case "labelbox-api-key":
			result, _ := runTargetFixture(t, rule, fixture, 200, `{"data":{"user":null}}`, false)
			assert.Equal(t, report.ValidationStatusInvalid, result.Status)
			assert.Empty(t, result.Analysis)
			for _, body := range []string{`{"data":{"user":{"id":"lbx-user"}},"errors":[{"message":"denied"}]}`, `{"data":{"user":null},"errors":[{"message":"Internal server error"}]}`} {
				result, _ = runTargetFixture(t, rule, fixture, 200, body, false)
				assert.Equal(t, report.ValidationStatusUnknown, result.Status)
				assert.Empty(t, result.Analysis)
			}
			_, analysis := runTargetFixture(t, rule, fixture, 200, `{"data":{"user":{"id":"lbx-user","organization":null}}}`, true)
			assert.Equal(t, &report.AnalysisIdentity{ID: "lbx-user"}, analysis.Identity)
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

func TestRecursionAPIKeyValidation(t *testing.T) {
	fixture := targetFixture{
		ruleID:     "labelbox-recursion-api-key",
		url:        "https://api.recursion.labelbox.com/managed-agents/v1/models",
		authHeader: "Authorization",
		authValue:  "Bearer fixture-secret-us20",
	}
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   report.ValidationStatus
	}{
		{"organization key", 200, `{"data":[]}`, report.ValidationStatusValid},
		{"tenant key without organization", 400, `{"code":"invalid_request","message":"Send x-organization-id with a tenant-scoped API key."}`, report.ValidationStatusValid},
		{"other bad request", 400, `{"code":"invalid_request"}`, report.ValidationStatusUnknown},
		{"unauthorized", 401, `{"code":"unauthorized","message":"This endpoint requires a Recursion API key."}`, report.ValidationStatusInvalid},
		{"rate limited", 429, `{}`, report.ValidationStatusUnknown},
		{"unavailable", 503, `{}`, report.ValidationStatusUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, _ := runTargetFixture(t, testRule(t, fixture.ruleID), fixture, test.status, test.body, false)
			assert.Equal(t, test.want, result.Status)
		})
	}
}
