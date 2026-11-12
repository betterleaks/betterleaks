package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "lighton-paradigm-api-key",
	Confidence:  "medium",
	Description: "Detected a LightOn Paradigm API key, which may expose enterprise LLM services to unauthorized access.",
	Regex:       rulebuilder.Assignment([]string{"lighton", "paradigm"}, `(?i)[A-Za-z0-9_\-]{40,80}`),
	Keywords:    []string{"lighton", "paradigm"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	ValidateExpr: `let r = http.get("https://paradigm.lighton.ai/api/v2/models", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"object"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("paradigm assignment", `paradigmToken = "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"`, "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"),
		rulebuilder.Match("lighton assignment", `lightonToken = "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"`, "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"),
		rulebuilder.NoMatch("Low entropy", `paradigm_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
	},
})
