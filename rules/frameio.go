package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Found a Frame.io API token, potentially compromising video collaboration and project management.",
	ID:          "frameio-api-token",
	Confidence:  "high",
	Regex:       `fio-u-(?i)[a-z0-9\-_=]{64}`,
	Keywords:    []string{"fio-u-"},
	ValidateExpr: `let r = http.get("https://api.frame.io/v2/me", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.3),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `frameioToken = "fio-u-ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r"`, "fio-u-ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7=55r"),
	},
})
