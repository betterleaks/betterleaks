package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "rainforest-pay-production-api-key",
	Confidence:  "medium",
	Description: "Rainforest Pay production API key.",
	Regex: rulebuilder.Assignment(
		[]string{`rainforest(?:[_. -]*pay)?(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
		`apikey_[a-f0-9]{64}`,
	),
	Keywords: []string{"rainforest"},
	ValidateExpr: `let r = http.get("https://api.rainforestpay.com/v1/merchants?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Rainforest-Api-Version": "2024-10-16",
    "Accept": "application/json"
  }); r.status == 200 && (r.json?.status ?? "") == "SUCCESS" ? {
    "result": "valid"
  } : r.status == 403 && (r.json?.status ?? "") == "ERROR" ? {
    "result": "valid",
    "reason": "Authenticated but merchant access is restricted"
  } : r.status == 401 && (r.json?.status ?? "") == "ERROR" ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "RAINFOREST_API_KEY=apikey_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc", "apikey_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.NoMatch("false positive 1", "RAINFOREST_API_KEY=sbx_apikey_2bd2c646e7e1194f8c9cf194e8f4555de1f3eefbbc472003276666d4efb76e74"),
		rulebuilder.NoMatch("false positive 2", "API_KEY=apikey_1ad1c535b0c0093e7b9bf093d7e3444cd0e2ddefab36199216f555c3efa65d63"),
		rulebuilder.NoMatch("false positive 3", "RAINFOREST_API_KEY=apikey_0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
