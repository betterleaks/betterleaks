package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Access and refresh tokens share this format, and both types are
// data-center-specific. The fixed US CRM check can prove a matching access
// token valid, but every non-success remains unknown rather than incorrectly
// rejecting a refresh token or a credential issued in another region.
var _ = rulebuilder.Add(config.Rule{
	ID:          "zoho-oauth-token.1",
	Confidence:  "high",
	Description: "Zoho OAuth access or refresh token, which may allow access to Zoho APIs or minting of new access tokens.",
	Regex:       rulebuilder.Assignment([]string{"zoho"}, `(?i)1000\.`+rulebuilder.Hex("32")+`\.`+rulebuilder.Hex("32")),
	Keywords:    []string{"zoho"},
	ValidateExpr: `let r = http.get("https://www.zohoapis.com/crm/v8/users?type=CurrentUser", {
    "Authorization": "Zoho-oauthtoken " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"users\"") ? {
    "result": "valid"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `zoho_oauthToken = "1000.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"`, "1000.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.Match("true positive 1", "ZOHO_ACCESS_TOKEN=1000.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc", "1000.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.Match("true positive 2", `zoho-refresh-token: "1000.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"`, "1000.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.NoMatch("false positive 1", "ACCESS_TOKEN=1000.0123456789abcdef0123456789abcdef.fedcba9876543210fedcba9876543210"),
		rulebuilder.NoMatch("false positive 2", "ZOHO_ACCESS_TOKEN=1000.24baa4103269e50e.41fa7dd2b88dd4d4"),
		rulebuilder.NoMatch("false positive 3", "ZOHO_CLIENT_ID=1000.9A2N2IKWOJB2F0BZGTJLYAK930GZJG"),
		rulebuilder.NoMatch("false positive 4", "ZOHO_ACCESS_TOKEN=1000.00000000000000000000000000000000.00000000000000000000000000000000"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "zoho-client-id.1",
	Confidence:  "medium",
	Description: "Zoho OAuth client ID, used as a component of the zoho-client-secret.1 composite rule.",
	Regex:       rulebuilder.Assignment([]string{"zoho"}, `(?i)1000\.`+rulebuilder.AlphaNumeric("30")),
	Keywords:    []string{"zoho"},
	SkipReport:  true,
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "ZOHO_CLIENT_ID=1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP", "1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.MatchComponent("true positive 2", `zoho.client_id: "1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"`, "1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.MatchComponent("true positive 3", "response_type=code&zoho_client_id=1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP", "1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.NoMatchComponent("false positive 1", "CLIENT_ID=1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"),
		rulebuilder.NoMatchComponent("false positive 2", "ZOHO_CLIENT_ID=1000.short"),
		rulebuilder.NoMatchComponent("false positive 3", "ZOHO_ACCESS_TOKEN=1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4"),
		rulebuilder.NoMatchComponent("false positive 4", "ZOHO_CLIENT_ID=1000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})

// Zoho clients and client secrets are data-center-specific. A deliberately
// invalid authorization code proves that a pair reached grant validation,
// but all other responses remain unknown because invalid_client can also
// mean that a valid pair was sent to the wrong Zoho accounts region.
var _ = rulebuilder.Add(config.Rule{
	ID:          "zoho-client-secret.1",
	Confidence:  "high",
	Description: "Zoho OAuth client secret, which may allow OAuth client authentication when paired with the associated client ID.",
	Regex:       rulebuilder.Assignment([]string{"zoho"}, `(?i)`+rulebuilder.Hex("42")),
	Keywords:    []string{"zoho"},
	Components: []config.Component{
		{RuleID: "zoho-client-id.1", Within: "5L"},
	},
	ValidateExpr: `let r = http.post("https://accounts.zoho.com/oauth/v2/token", {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  }, "client_id=" + strings.urlQueryEscape((components["zoho-client-id.1"]?.secret ?? "")) +
  "&client_secret=" + strings.urlQueryEscape(finding["secret"]) +
  "&grant_type=authorization_code" +
  "&code=betterleaks_invalid_code" +
  "&redirect_uri=https%3A%2F%2Fexample.com%2Fbetterleaks");
  r.status == 200 && (r.json?.error ?? "") == "invalid_code" ? {
    "result": "valid"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "ZOHO_CLIENT_SECRET=1f7b169c846f218ab552fa82fbf86758bf5c97d2d2\nZOHO_CLIENT_ID=1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP",
			Expect: []config.ExpectedFinding{
				{Secret: "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2", ComponentSets: []map[string]string{{"zoho-client-id.1": "1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "zoho client_secret: \"1f7b169c846f218ab552fa82fbf86758bf5c97d2d2\"\nZOHO_CLIENT_ID=1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP",
			Expect: []config.ExpectedFinding{
				{Secret: "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2", ComponentSets: []map[string]string{{"zoho-client-id.1": "1000.RFbD56TI2smTyVsGd5Xav0yu99ZAMP"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "CLIENT_SECRET=1f7b169c846f218ab552fa82fbf86758bf5c97d2d2"),
		rulebuilder.NoMatch("false positive 2", "ZOHO_CLIENT_SECRET=ec8970658937efb63d126f73b57b0aa47bf4f2d7d"),
		rulebuilder.NoMatch("false positive 3", "ZOHO_CLIENT_SECRET=000000000000000000000000000000000000000000"),
	},
})

// ZAPI keys authorize a particular Zoho function or webhook. Validation
// requires that function's provider-owned URL, which cannot be reconstructed
// safely from the key alone.
var _ = rulebuilder.Add(config.Rule{
	ID:          "zoho-zapi-key.1",
	Confidence:  "high",
	Description: "Zoho ZAPI key, which may authorize CRM functions, extensions, webhooks, or other Zoho APIs.",
	Regex: rulebuilder.Assignment(
		[]string{"zoho"},
		`(?i)(?:1001\.`+rulebuilder.Hex("32")+`\.`+rulebuilder.Hex("32")+`(?:-d)?|1003\.`+rulebuilder.Hex("32,64")+`)`,
	),
	Keywords:   []string{"zoho"},
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ZOHO_ZAPI_KEY=1001.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc", "1001.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.Match("true positive 2", "Zoho-zapikey=1001.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc-d", "1001.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc-d"),
		rulebuilder.Match("true positive 3", "ZOHO_ZAPI_KEY=1003.1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4", "1003.1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4"),
		rulebuilder.NoMatch("false positive 1", "ZAPI_KEY=1001.bf5c97d2d2a313e4f95957818a7b3edc.bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.NoMatch("false positive 2", "ZOHO_ZAPI_KEY=1001.short"),
		rulebuilder.NoMatch("false positive 3", "ZOHO_ZAPI_KEY=1000.1fa6966eafbb115624baa4103269e50e.e57d155232227b4e41fa7dd2b88dd4d4"),
		rulebuilder.NoMatch("false positive 4", "ZOHO_ZAPI_KEY=1001.00000000000000000000000000000000.00000000000000000000000000000000"),
	},
})
