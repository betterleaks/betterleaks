package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://docs.cohere.com/reference/check-api-key
const cohereValidateExpr = `let r = http.post("https://api.cohere.com/v1/check-api-key", {
  "Authorization": "Bearer " + finding["secret"], "Content-Type": "application/json", "Accept": "application/json"
}, "{}");
let body = type(r.json) == "map" ? r.json : {};

r.status == 200 && (body?.valid == true) ? {
  "result": "valid", "analysis": {
    "id": type(body?.owner_id) == "string" ? body?.owner_id : "",
    "organization_id": type(body?.organization_id) == "string" ? body?.organization_id : ""
  }
} : r.status == 401 || (r.status == 200 && body?.valid == false) ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`
const cohereAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {
    "id": input["id"] ?? "",
    "account": {"id": input["organization_id"] ?? ""}
  },
  "capabilities": []
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "cohere-api-token",
	Confidence:  "medium",
	Description: "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
	Regex:       rulebuilder.Assignment([]string{"cohere", "CO_API_KEY"}, `[a-zA-Z0-9]{40}`),
	Keywords: []string{
		"cohere",
		"co_api_key",
	},
	ValidateExpr: cohereValidateExpr,
	FilterExpr:   `entropy(finding["secret"]) < 4.0 || tokenRatio(finding["secret"]) >= 2.5`,
	AnalyzeExpr:  cohereAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `cohere_api_token = "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"`, "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.Match("https://github.com/cohere-ai/cohere-go/blob/abe8044073ed498ffbb206a602d03c2414b64512/client/client.go#L38C30-L38C40", "export CO_API_KEY=RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k", "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.NoMatch("false positive 1", "CO_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
