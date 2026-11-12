package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "rootly-api-key.1",
	Confidence:  "high",
	Description: "Rootly API key.",
	Regex:       rulebuilder.Token(`rootly_[a-f0-9]{64}`),
	Keywords:    []string{"rootly_"},
	ValidateExpr: `let r = http.get("https://api.rootly.com/v1/incidents", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status in [200, 404] ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ROOTLY_API_KEY=rootly_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc", "rootly_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.NoMatch("false positive 1", "ROOTLY_API_KEY=rootly_short"),
		rulebuilder.NoMatch("false positive 2", "ROOTLY_API_KEY=rootly_0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
