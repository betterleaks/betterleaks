package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "brave-search-api-key",
	Confidence:  "high",
	Description: "Detected a Brave Search API key, which may allow unauthorized use of Brave Search API quota.",
	Regex:       `\b(BSA[A-Za-z0-9_-]{24,40})\b`,
	Keywords:    []string{"bsa"},
	ValidateExpr: `let r = http.get("https://api.search.brave.com/res/v1/web/search?q=betterleaks&count=1", {
    "Accept": "application/json",
    "X-Subscription-Token": finding["secret"]
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.2`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `BRAVE_SEARCH_API_KEY="BSAp7_Mi4q7zWv9NeL2asR0kF6hTbQx"`, "BSAp7_Mi4q7zWv9NeL2asR0kF6hTbQx"),
		rulebuilder.Match("true positive 2", `headers = {"X-Subscription-Token": "BSAk4_Vm8nDp3Qw7Ls0raF2jHx6ZuCt"}`, "BSAk4_Vm8nDp3Qw7Ls0raF2jHx6ZuCt"),
		rulebuilder.NoMatch("false positive 1", `BRAVE_SEARCH_API_KEY="BSAshort"`),
		rulebuilder.NoMatch("false positive 2", `BRAVE_SEARCH_API_KEY="BSAp7_Mi4q7zWv9NeL2asR0k"`),
	},
})
