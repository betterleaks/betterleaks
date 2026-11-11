package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "auth0-domain.1",
	Confidence:  "high",
	Description: "Auth0 tenant domain, used as a component of the Auth0 client-secret composite rule.",
	Regex: Token(
		`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+auth0\.com`,
	),
	Keywords:   []string{"auth0.com"},
	SkipReport: true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "AUTH0_DOMAIN=example-tenant.us.auth0.com",
			Expect: []config.ExpectedFinding{
				{Secret: "example-tenant.us.auth0.com"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `auth0_domain: "example.eu.auth0.com"`,
			Expect: []config.ExpectedFinding{
				{Secret: "example.eu.auth0.com"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "AUTH0_DOMAIN=auth0.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "AUTH0_DOMAIN=example-auth0.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 3",
			Mode:   "match",
			Input:  "AUTH0_DOMAIN=example.auth0.com.evil.example",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "auth0-client-id.1",
	Confidence:  "medium",
	Description: "Auth0 client ID, used as a component of the Auth0 client-secret composite rule.",
	Regex: Assignment(
		[]string{`auth0[_.-]?(?:client[_.-]?)?(?:id|identifier)`},
		`[A-Za-z0-9_-]{32,60}`,
	),
	Keywords:   []string{"auth0"},
	SkipReport: true,
	FilterExpr: MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "AUTH0_CLIENT_ID=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps",
			Expect: []config.ExpectedFinding{
				{Secret: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `auth0.client_id: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"`,
			Expect: []config.ExpectedFinding{
				{Secret: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "CLIENT_ID=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "AUTH0_CLIENT_ID=short",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 3",
			Mode:   "match",
			Input:  "AUTH0_CLIENT_ID=00000000000000000000000000000000",
			Expect: []config.ExpectedFinding{},
		},
	},
})

// The invalid authorization code reaches grant validation only after Auth0
// accepts the tenant, client ID, and client secret. An invalid_client error
// is therefore a definitive rejection of the discovered credential pair.
var _ = Add(config.Rule{
	ID:          "auth0-client-secret.1",
	Confidence:  "high",
	Description: "Auth0 client secret, which may allow an application to impersonate its OAuth client.",
	Regex: Assignment(
		[]string{`auth0[_.-]?(?:client[_.-]?)?(?:secret|private|key|token)`},
		`[A-Za-z0-9_-]{64,128}`,
	),
	Keywords: []string{"auth0"},
	Components: []config.Component{
		{RuleID: "auth0-client-id.1", Within: "10L"},
		{RuleID: "auth0-domain.1", Within: "10L"},
	},
	ValidateExpr: `let domain = (components["auth0-domain.1"]?.secret ?? "");
let clientID = (components["auth0-client-id.1"]?.secret ?? "");
let r = http.post("https://" + domain + "/oauth/token", {
  "Accept": "application/json",
  "Content-Type": "application/x-www-form-urlencoded"
}, "grant_type=authorization_code" +
  "&client_id=" + strings.urlQueryEscape(clientID) +
  "&client_secret=" + strings.urlQueryEscape(finding["secret"]) +
  "&code=betterleaks_invalid_code" +
  "&redirect_uri=https%3A%2F%2Fexample.com%2Fbetterleaks");
let oauthError = (r.json?.error ?? "");
oauthError == "invalid_grant" ? {
  "result": "valid"
} : oauthError == "invalid_client" ? {
  "result": "invalid",
  "reason": "Invalid Auth0 client credentials"
} : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "AUTH0_CLIENT_SECRET=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR\nAUTH0_CLIENT_ID=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps\nAUTH0_DOMAIN=example-tenant.us.auth0.com",
			Expect: []config.ExpectedFinding{
				{Secret: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR", ComponentSets: []map[string]string{{"auth0-client-id.1": "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps", "auth0-domain.1": "example-tenant.us.auth0.com"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "auth0.client_secret: \"WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR\"\nAUTH0_CLIENT_ID=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps\nAUTH0_DOMAIN=example-tenant.us.auth0.com",
			Expect: []config.ExpectedFinding{
				{Secret: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR", ComponentSets: []map[string]string{{"auth0-client-id.1": "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps", "auth0-domain.1": "example-tenant.us.auth0.com"}}},
			},
		},
		NoMatch("false positive 1", "CLIENT_SECRET=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR"),
		NoMatch("false positive 2", "AUTH0_CLIENT_SECRET=short"),
		NoMatch("false positive 3", "AUTH0_CLIENT_SECRET=0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
