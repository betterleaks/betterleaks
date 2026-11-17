package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Reuse the existing OAuth exchange; never retain the minted bearer token.
// https://developer.paypal.com/api/rest/authentication
// Scope contracts: https://github.com/paypal/paypal-rest-api-specifications/tree/main/openapi
const paypalValidateExpr = `let r = http.post("https://api-m.paypal.com/v1/oauth2/token", {
  "Authorization": "Basic " + base64.encode(bytes((components["paypal-client-id.1"]?.secret ?? "") + ":" + finding["secret"])),
  "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"
}, "grant_type=client_credentials");
let body = type(r.json) == "map" ? r.json : {};
r.status == 200 && type(body?.access_token) == "string" && body.access_token != "" ? {
  "result": "valid", "analysis": {
    "app_id": type(body?.app_id) == "string" ? body.app_id : "",
    "scopes": type(body?.scope) == "string" ? strings.splitTrim(body.scope, " ") : []
  }
} : validate.unknown(r)`
const paypalAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let capabilities = analysis.capabilities({
  "read": any(scopes, {# in ["https://uri.paypal.com/services/disputes/read-buyer", "https://uri.paypal.com/services/disputes/read-seller", "https://uri.paypal.com/services/reporting/search/read", "https://uri.paypal.com/services/vault/payment-tokens/read"]}),
  "write": any(scopes, {# in ["https://uri.paypal.com/services/payments/refund", "https://uri.paypal.com/services/payments/payment/authcapture", "https://uri.paypal.com/payments/payouts", "https://uri.paypal.com/services/disputes/update-seller"]})
});
{
  "metadata": fromPairs(filter(toPairs({"app_id": input["app_id"] ?? "", "scopes": scopes}), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": capabilities
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "paypal-client-id.1",
	Confidence:  "medium",
	Description: "PayPal OAuth client ID, used as a component of the PayPal client-secret composite rule.",
	Regex:       rulebuilder.Assignment([]string{`paypal[_.-]?(?:client[_.-]?)?(?:id|user)`}, `A[A-Za-z0-9_-]{78,99}`),
	Keywords:    []string{"paypal"},
	SkipReport:  true,
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "PAYPAL_CLIENT_ID=AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f", "AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f"),
		rulebuilder.NoMatchComponent("false positive 1", "CLIENT_ID=AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f"),
		rulebuilder.NoMatchComponent("false positive 2", "PAYPAL_CLIENT_ID=Ashort"),
		rulebuilder.NoMatchComponent("false positive 3", "PAYPAL_CLIENT_ID=A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	},
})

// Sandbox and production credentials share their shape. The production
// token endpoint can prove a matching pair valid; a rejection remains
// unknown rather than misclassifying sandbox credentials.
var _ = rulebuilder.Add(config.Rule{
	ID:          "paypal-client-secret.1",
	Confidence:  "high",
	Description: "PayPal OAuth client secret, which may allow access to PayPal REST APIs when paired with its client ID.",
	Regex: rulebuilder.Assignment(
		[]string{`paypal[_.-]?(?:client[_.-]?)?(?:secret|private|access|key|token)`},
		`[A-Za-z0-9_.-]{78,120}`,
	),
	Keywords: []string{"paypal"},
	Components: []config.Component{
		{RuleID: "paypal-client-id.1", Within: "5L"},
	},
	ValidateExpr: paypalValidateExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	AnalyzeExpr:  paypalAnalyzeExpr,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "PAYPAL_CLIENT_SECRET=YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTF\nPAYPAL_CLIENT_ID=AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f",
			Expect: []config.ExpectedFinding{
				{Secret: "YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTF", ComponentSets: []map[string]string{{"paypal-client-id.1": "AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "CLIENT_SECRET=YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTF"),
		rulebuilder.NoMatch("false positive 2", "PAYPAL_CLIENT_SECRET=short"),
		rulebuilder.NoMatch("false positive 3", "PAYPAL_CLIENT_SECRET=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	},
})
