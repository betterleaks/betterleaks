package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "zai-api-key",
	Confidence:  "medium",
	Description: "Detected a Z.ai API key, which may expose GLM model access and usage to unauthorized parties.",
	Regex:       Assignment([]string{"zai", "z_ai", `z\.ai`, "glm", "zlm"}, `(?i)`+Hex("32")+`\.`+AlphaNumeric("16")),
	Keywords:    []string{"zai", "z_ai", "z.ai", "glm", "zlm"},
	ValidateExpr: `let r = http.post("https://api.z.ai/api/paas/v4/tokenizer", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json",
    "Content-Type": "application/json"
  },
  "{" +
    "\"model\":\"glm-4.6\"," +
    "\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]" +
  "}"); r.status == 200 && (r.body contains '"usage"') ? {
    "result": "valid"
  } : r.status == 429 && (r.body contains "Insufficient balance") ? {
    "result": "valid",
    "reason": "Insufficient balance but still valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("zai assignment", `zaiToken = "cbe5985d07804065b46efaf1daa82834.ZLV4IOHGbEEHPDt5"`, "cbe5985d07804065b46efaf1daa82834.ZLV4IOHGbEEHPDt5"),
	},
})
