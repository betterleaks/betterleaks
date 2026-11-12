package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "databento-api-key",
	Confidence:  "high",
	Description: "Databento API key.",
	Regex:       rulebuilder.Assignment([]string{"databento"}, `(?i)db-[A-Za-z0-9]{29}`),
	Keywords:    []string{"databento"},
	ValidateExpr: `let r = http.get("https://hist.databento.com/v0/metadata.list_datasets", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"] + ":"))
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "DATABENTO_API_KEY=db-abc123def456ghi789jkl012mno34", "db-abc123def456ghi789jkl012mno34"),
		rulebuilder.NoMatch("false positive 1", "db-short"),
	},
})
