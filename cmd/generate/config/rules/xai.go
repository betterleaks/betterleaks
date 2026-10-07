package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func XAI() *config.Rule {
	r := config.Rule{
		RuleID:      "xai-api-key",
		Confidence:  "high",
		Description: "Detected an xAI (Grok) API Key, which may expose Grok AI model access to unauthorized parties.",
		Regex:       utils.GenerateUniqueTokenRegex(`xai-[A-Za-z0-9_-]{70,120}`, true),
		Keywords:    []string{"xai-"},
		Filter:      `entropy(finding["secret"]) <= 3.5`,
		ValidateExpr: `let r = http.get("https://api.x.ai/v1/api-key", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.api_key_id) == "string" && r.json.api_key_id != "" &&
  (r.json?.api_key_disabled == true || r.json?.api_key_blocked == true || r.json?.team_blocked == true) ? {
  "result": "invalid",
  "reason": "xAI API key or owning team is disabled/blocked"
} : r.status == 200 && type(r.json) == "map" && type(r.json?.api_key_id) == "string" && r.json.api_key_id != "" ? {
  "result": "valid"
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)
`,
	}

	tps := utils.GenerateSampleSecrets("xai", "xai-"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{84}`, 3.5))
	fps := []string{
		// Too short
		`xai-CNPlxZEZVpxDTRD8N6Luet7LwS2qyuijh7pdHbmNzsw`,
		// Wrong prefix
		`xbi-CNPlxZEZVpxDTRD8N6Luet7LwS2qyuijh7pdHbmNzswLAYSWUeODm8Cav2On1LqgrCewPvGCWxBqSbh3`,
	}
	return utils.Validate(r, tps, fps)
}
