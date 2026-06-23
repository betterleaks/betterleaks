package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func ZAIAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "zai-api-key",
		Description: "Detected a Z.ai API key, which may expose GLM model access and usage to unauthorized parties.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"zai", "z_ai", `z\.ai`, "glm", "zlm"}, utils.Hex("32")+`\.`+utils.AlphaNumeric("16"), true),
		Keywords:    []string{"zai", "z_ai", "z.ai", "glm", "zlm"},
		ValidateCEL: `let r = http.post("https://api.z.ai/api/paas/v4/tokenizer", {
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
		Filter: `entropy(finding["secret"]) <= 3.5`,
	}

	tps := append(
		utils.GenerateSampleSecrets("zai", "cbe5985d07804065b46efaf1daa82834.ZLV4IOHGbEEHPDt5"),
	)
	fps := []string{}
	return utils.Validate(r, tps, fps)
}
