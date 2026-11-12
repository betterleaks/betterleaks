package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "datagov-api-key",
	Confidence:  "high",
	Description: "Detected a Data.gov API key, which may expose usage of Data.gov-backed APIs.",
	Regex:       rulebuilder.Assignment([]string{`data\.gov`}, `(?i)[a-z0-9]{40}`),
	Keywords:    []string{"data.gov"},
	ValidateExpr: `let r = http.get("https://developer.nrel.gov/api/alt-fuel-stations/v1.json?limit=1&api_key=" + finding["secret"], {
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "data.gov_api_key=pBZm2kXbuPdRfzYyarRT0bvcWAisnJg98YJzBJyJ", "pBZm2kXbuPdRfzYyarRT0bvcWAisnJg98YJzBJyJ"),
		rulebuilder.Match("true positive 2", "data.gov_token=plZJDnKs4OrPeV8wgBr2fYO6VnXb1YPEcVaZbnYI", "plZJDnKs4OrPeV8wgBr2fYO6VnXb1YPEcVaZbnYI"),
	},
})
