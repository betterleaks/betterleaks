package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "kimi-api-key",
	Confidence:  "high",
	Description: "Detected a Kimi API key, which may expose Moonshot AI model access and usage to unauthorized parties.",
	Regex:       Assignment([]string{"kimi", "moonshot"}, `(?i)sk-[A-Za-z0-9_-]{48}`),
	Keywords:    []string{"kimi", "moonshot"},
	ValidateExpr: `let r = http.get("https://api.moonshot.ai/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("kimi assignment", `kimiToken = "sk-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"`, "sk-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"),
		Match("moonshot assignment", `moonshotToken = "sk-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"`, "sk-WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"),
		NoMatch("false positive 1", `api_key = "sk-uBf3S6jw9Akw0X6u9KDygGb5rDn1LdZ7G3mVtvHhQb7x0sMn"`),
		NoMatch("false positive 2", `kimi_api_key = "sk-uBf3S6jw9Akw0X6u9KDy"`),
		NoMatch("false positive 3", `moonshot_api_key = "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`),
	},
})
