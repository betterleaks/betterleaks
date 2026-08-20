package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Auth0Domain() *config.Rule {
	r := config.Rule{
		RuleID:      "auth0-domain.1",
		Confidence:  "high",
		Description: "Auth0 tenant domain, used as a component of the Auth0 client-secret composite rule.",
		Regex: utils.GenerateUniqueTokenRegex(
			`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+auth0\.com`,
			true,
		),
		Keywords:   []string{"auth0.com"},
		SkipReport: true,
	}

	tps := []string{
		`AUTH0_DOMAIN=example-tenant.us.auth0.com`,
		`auth0_domain: "example.eu.auth0.com"`,
	}
	fps := []string{
		`AUTH0_DOMAIN=auth0.com`,
		`AUTH0_DOMAIN=example-auth0.com`,
		`AUTH0_DOMAIN=example.auth0.com.evil.example`,
	}
	return utils.Validate(r, tps, fps)
}

func Auth0ClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "auth0-client-id.1",
		Confidence:  "medium",
		Description: "Auth0 client ID, used as a component of the Auth0 client-secret composite rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`auth0[_.-]?(?:client[_.-]?)?(?:id|identifier)`},
			`[A-Za-z0-9_-]{32,60}`,
			false,
		),
		Keywords:   []string{"auth0"},
		SkipReport: true,
		Filter:     utils.MinEntropy(3.0),
	}

	clientID := secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{32}`, 3.0)
	tps := []string{
		`AUTH0_CLIENT_ID=` + clientID,
		`auth0.client_id: "` + clientID + `"`,
	}
	fps := []string{
		`CLIENT_ID=` + clientID,
		`AUTH0_CLIENT_ID=short`,
		`AUTH0_CLIENT_ID=00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func Auth0ClientSecret() *config.Rule {
	// The invalid authorization code reaches grant validation only after Auth0
	// accepts the tenant, client ID, and client secret. An invalid_client error
	// is therefore a definitive rejection of the discovered credential pair.
	r := config.Rule{
		RuleID:      "auth0-client-secret.1",
		Confidence:  "high",
		Description: "Auth0 client secret, which may allow an application to impersonate its OAuth client.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`auth0[_.-]?(?:client[_.-]?)?(?:secret|private|key|token)`},
			`[A-Za-z0-9_-]{64,128}`,
			false,
		),
		Keywords: []string{"auth0"},
		Components: []*config.Component{
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
		Filter: utils.MinEntropy(3.5),
	}

	clientSecret := secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{64}`, 3.5)
	tps := []string{
		`AUTH0_CLIENT_SECRET=` + clientSecret,
		`auth0.client_secret: "` + clientSecret + `"`,
	}
	fps := []string{
		`CLIENT_SECRET=` + clientSecret,
		`AUTH0_CLIENT_SECRET=short`,
		`AUTH0_CLIENT_SECRET=0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
