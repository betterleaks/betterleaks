package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "civo-api-key",
	Confidence:  "high",
	Description: "Detected a Civo Cloud API key, which may expose Kubernetes clusters and compute resources to unauthorized access.",
	Regex:       Assignment([]string{"civo"}, `(?i)`+AlphaNumeric("50")),
	Keywords:    []string{"civo"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	ValidateExpr: `let r = http.get("https://api.civo.com/v2/instances", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		Match("civo assignment", `civoToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl"),
		NoMatch("Low entropy", `civo_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
	},
})
