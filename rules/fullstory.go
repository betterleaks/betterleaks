package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://developer.fullstory.com/server/authentication/
// /me reports the key role, not merely the owning user role. Basic takes the
// raw key; api.fullstory.com automatically routes both na1 and eu1 keys.
const fullstoryValidateExpr = `let r = http.get("https://api.fullstory.com/me", {
  "Authorization": "Basic " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.role) == "string" && r.json.role != "" ? {
  "result": "valid",
  "analysis": {
    "role": r.json.role
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const fullstoryAnalyzeExpr = `let role = validation.analysis["role"] ?? "";
let known = role in ["USER", "ARCHITECT", "ADMIN"];
{
  "metadata": {"role": role},
  "capabilities": analysis.capabilities({"read": known, "write": known, "admin": role == "ADMIN"}),
  "reason": known ? "" : "Fullstory returned an unrecognized API key role"
}`

var _ = Add(config.Rule{
	ID:          "fullstory-api-key",
	Confidence:  "medium",
	Description: "FullStory API key.",
	Regex: Assignment(
		[]string{`(?:fullstory|fs_api|fullstory_api)`},
		`(?i)(?:na1|eu1)\.[A-Za-z0-9]{20,}`,
	),
	Keywords:     []string{"fullstory", "fs_api"},
	ValidateExpr: fullstoryValidateExpr,
	AnalyzeExpr:  fullstoryAnalyzeExpr,
	FilterExpr:   MinEntropy(3.3),
	Tests: []config.RuleTest{
		Match("true positive 1", `fullstory_api_token = "na1.5fbbd6p84oe7ut4qrttebiwar77s63do"`, "na1.5fbbd6p84oe7ut4qrttebiwar77s63do"),
		NoMatch("false positive 1", "FULLSTORY_API_KEY=na1.short"),
	},
})
