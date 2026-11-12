package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "cohere-api-token",
	Confidence:  "medium",
	Description: "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
	Regex:       rulebuilder.Assignment([]string{"cohere", "CO_API_KEY"}, `[a-zA-Z0-9]{40}`),
	Keywords: []string{
		"cohere",
		"co_api_key",
	},
	ValidateExpr: `let r = http.get("https://api.cohere.com/v1/connectors", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"connectors"') && (r.body contains '"total_count"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 4.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `cohere_api_token = "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"`, "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.Match("https://github.com/cohere-ai/cohere-go/blob/abe8044073ed498ffbb206a602d03c2414b64512/client/client.go#L38C30-L38C40", "export CO_API_KEY=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k", "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.NoMatch("false positive 1", "CO_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
