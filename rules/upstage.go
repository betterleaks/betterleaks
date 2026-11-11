package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "upstage-api-key",
	Confidence:  "medium",
	Description: "Detected an Upstage AI API key, which may expose Solar language models and document AI services to unauthorized access.",
	Regex:       Assignment([]string{"upstage"}, `(?i)[A-Za-z0-9]{40,50}`),
	Keywords:    []string{"upstage"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	ValidateExpr: `let r = http.get("https://api.upstage.ai/v1/models", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("upstage assignment", `upstageToken = "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"`, "RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		NoMatch("Low entropy", `upstage_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
	},
})
