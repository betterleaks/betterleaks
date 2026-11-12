package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "gocardless-api-token",
	Confidence:  "high",
	Description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
	Regex:       rulebuilder.Assignment([]string{"gocardless"}, `(?i)live_(?i)[a-z0-9\-_=]{40}`),
	Keywords: []string{
		"live_",
		"gocardless",
	},
	ValidateExpr: `let r = http.get("https://api.gocardless.com/customers?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json",
    "GoCardless-Version": "2015-07-06"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `gocardlessToken = "live_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"`, "live_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"),
	},
})
