package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "tavily-api-key",
	Confidence:  "high",
	Description: "Detected a Tavily API key, which may allow access to Tavily AI search APIs and account usage details.",
	Regex:       rulebuilder.Token(`(?:tvly-[A-Za-z0-9]{32}|tvly-[A-Za-z0-9]{6}-[A-Za-z0-9]{42})`),
	Keywords:    []string{"tvly-"},
	ValidateExpr: `let r = http.get("https://api.tavily.com/usage", {"Authorization": "Bearer " + finding["secret"]});
(r.status in [200]) ? {
    "result": "valid"
  } :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `token = "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"`, `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`),
		rulebuilder.Match("shape 2", `token = "tvly-yzLFs7-oniA6wrcaKrgxxmGhciOsQVksW7LwL8Eq4IMYjY2Bg"`, `tvly-yzLFs7-oniA6wrcaKrgxxmGhciOsQVksW7LwL8Eq4IMYjY2Bg`),
		rulebuilder.NoMatch("near miss 1", `token = "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"`),
		rulebuilder.NoMatch("near miss 2", `token = "tvly-ZaoQ8i-NGxPCORwFmJSaxvWdRWXj8fTsinmBGA4nlVpQRO8A"`),
	},
})
