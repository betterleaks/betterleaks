package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Read-only token introspection; production OAuth and personal access tokens.
// A rejected token may belong to Sandbox, so a production rejection stays unknown.
// https://developer.squareup.com/reference/square/oauth-api/retrieve-token-status
// https://developer.squareup.com/docs/oauth-api/square-permissions
const squareValidateExpr = `let r = http.post("https://connect.squareup.com/oauth2/token/status", {
  "Authorization": "Bearer " + finding["secret"], "Content-Type": "application/json",
  "Accept": "application/json", "Square-Version": "2026-09-16"
}, "{}");
let body = type(r.json) == "map" ? r.json : {};
r.status == 200 && type(body?.merchant_id) == "string" && body.merchant_id != "" && type(body?.scopes) == "array" && all(body.scopes, {type(#) == "string"}) ? {
  "result": "valid", "analysis": {
    "merchant_id": body.merchant_id,
    "client_id": type(body?.client_id) == "string" ? body.client_id : "",
    "scopes": filter(body.scopes, {type(#) == "string"}),
    "expires_at": type(body?.expires_at) == "string" ? body.expires_at : nil
  }
} : validate.unknown(r)`
const squareAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let capabilities = analysis.capabilities({
  "read": any(scopes, {# in ["PAYMENTS_READ", "ORDERS_READ", "CUSTOMERS_READ", "ITEMS_READ", "INVENTORY_READ", "MERCHANT_PROFILE_READ", "BANK_ACCOUNTS_READ", "EMPLOYEES_READ", "TIMECARDS_READ", "INVOICES_READ", "LOYALTY_READ", "GIFTCARDS_READ", "APPOINTMENTS_READ", "PAYOUTS_READ", "VENDOR_READ"]}),
  "write": any(scopes, {# in ["PAYMENTS_WRITE", "ORDERS_WRITE", "CUSTOMERS_WRITE", "ITEMS_WRITE", "INVENTORY_WRITE", "EMPLOYEES_WRITE", "TIMECARDS_WRITE", "INVOICES_WRITE", "LOYALTY_WRITE", "GIFTCARDS_WRITE", "APPOINTMENTS_WRITE", "VENDOR_WRITE"]})
});
{
  "identity": {"account": {"id": input["merchant_id"] ?? ""}},
  "metadata": fromPairs(filter(toPairs({"client_id": input["client_id"] ?? "", "scopes": scopes, "expires_at": input["expires_at"]}), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": capabilities
}`

var _ = rulebuilder.Add(config.Rule{
	ID:           "square-access-token",
	Confidence:   "high",
	Description:  "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
	Regex:        rulebuilder.Token(`(?:EAAA|sq0atp-)[\w-]{22,60}`),
	Keywords:     []string{"sq0atp-", "eaaa"},
	FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	ValidateExpr: squareValidateExpr,
	AnalyzeExpr:  squareAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `squareToken = "sq0atp-E6v05tg7Z5jXlNPAK_XEPc"`, "sq0atp-E6v05tg7Z5jXlNPAK_XEPc"),
		rulebuilder.Match("true positive 1", "ARG token=sq0atp-812erere3wewew45678901", "sq0atp-812erere3wewew45678901"),
		rulebuilder.Match("true positive 2", "ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E", "EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E"),
		rulebuilder.NoMatch("false positive 1", "aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00"),
	},
})

// SquareSecret has never been registered in the default config.
func SquareSecret() config.Rule {
	return config.Rule{
		ID:          "square-secret",
		Confidence:  "high",
		Description: "Square Secret",
		Regex:       rulebuilder.Token(`sq0csp-[\w-]{43}`),
		Keywords:    []string{"sq0csp-"},
		FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
		Tests: []config.RuleTest{
			rulebuilder.Match("true positive 1", `value: "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY"`, "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY"),
		},
	}
}
