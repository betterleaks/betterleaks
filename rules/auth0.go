package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "auth0-domain.1",
	Confidence:  "high",
	Description: "Auth0 tenant domain, used as a component of the Auth0 client-secret composite rule.",
	Regex:       rulebuilder.Token(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+auth0\.com`),
	Keywords:    []string{"auth0.com"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "AUTH0_DOMAIN=example-tenant.us.auth0.com", "example-tenant.us.auth0.com"),
		rulebuilder.MatchComponent("true positive 2", `auth0_domain: "example.eu.auth0.com"`, "example.eu.auth0.com"),
		rulebuilder.NoMatchComponent("false positive 1", "AUTH0_DOMAIN=auth0.com"),
		rulebuilder.NoMatchComponent("false positive 2", "AUTH0_DOMAIN=example-auth0.com"),
		rulebuilder.NoMatchComponent("false positive 3", "AUTH0_DOMAIN=example.auth0.com.evil.example"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "auth0-client-id.1",
	Confidence:  "medium",
	Description: "Auth0 client ID, used as a component of the Auth0 client-secret composite rule.",
	Regex: rulebuilder.Assignment(
		[]string{`auth0[_.-]?(?:client[_.-]?)?(?:id|identifier)`},
		`[A-Za-z0-9_-]{32,60}`,
	),
	Keywords:   []string{"auth0"},
	SkipReport: true,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "AUTH0_CLIENT_ID=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps", "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"),
		rulebuilder.MatchComponent("true positive 2", `auth0.client_id: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"`, "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"),
		rulebuilder.NoMatchComponent("false positive 1", "CLIENT_ID=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"),
		rulebuilder.NoMatchComponent("false positive 2", "AUTH0_CLIENT_ID=short"),
		rulebuilder.NoMatchComponent("false positive 3", "AUTH0_CLIENT_ID=00000000000000000000000000000000"),
	},
})

// The invalid authorization code reaches grant validation only after Auth0
// accepts the tenant, client ID, and client secret. An invalid_client error
// is therefore a definitive rejection of the discovered credential pair.
var _ = rulebuilder.Add(config.Rule{
	ID:          "auth0-client-secret.1",
	Confidence:  "high",
	Description: "Auth0 client secret, which may allow an application to impersonate its OAuth client.",
	Regex: rulebuilder.Assignment(
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
	FilterExpr: rulebuilder.MinEntropy(3.5),
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
		rulebuilder.NoMatch("false positive 1", "CLIENT_SECRET=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxR"),
		rulebuilder.NoMatch("false positive 2", "AUTH0_CLIENT_SECRET=short"),
		rulebuilder.NoMatch("false positive 3", "AUTH0_CLIENT_SECRET=0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
