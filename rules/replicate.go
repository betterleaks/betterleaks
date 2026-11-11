package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://replicate.com/docs/reference/http#account.get
const replicateValidateExpr = `let r = http.get("https://api.replicate.com/v1/account", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && (r.json?.username ?? "") != "" && (r.json?.type ?? "") in ["user", "organization"] ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "username": r.json.type == "user" ? string(r.json.username) : "",
      "name": r.json.type == "user" ? string(r.json?.name ?? "") : "",
      "account": r.json.type == "organization" ? {"id": string(r.json.username), "name": string(r.json?.name ?? "")} : nil
    },
    "metadata": {
      "account_type": r.json.type
    }
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const replicateAnalyzeExpr = identityOnlyAnalyzeExpr

var _ = Add(config.Rule{
	ID:           "replicate-api-token",
	Confidence:   "high",
	Description:  "Detected a Replicate API Token, which may expose AI model hosting and inference services to unauthorized access.",
	Regex:        Token(`(?i)r8_[A-Za-z0-9]{37}`),
	Keywords:     []string{"r8_"},
	ValidateExpr: replicateValidateExpr,
	AnalyzeExpr:  replicateAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("replicate assignment", `replicateToken = "r8_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s5"`, "r8_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s5"),
		NoMatch("Too short", "r8_WesXNvqsCpq7r1gpQABpB3NJvdR"),
		NoMatch("Wrong prefix", "r9_WesXNvqsCpq7r1gpQABpB3NJvdR21nb2s7HVy"),
	},
})
