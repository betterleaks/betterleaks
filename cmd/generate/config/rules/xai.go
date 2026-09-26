package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://docs.x.ai/developers/rest-api-reference/inference/other
// Model/endpoint wildcards are not management API permissions.
const xaiValidateExpr = `let r = http.get("https://api.x.ai/v1/api-key", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.api_key_id) == "string" && r.json.api_key_id != "" &&
  (r.json?.api_key_disabled == true || r.json?.api_key_blocked == true || r.json?.team_blocked == true) ? {
  "result": "invalid",
  "reason": "xAI API key or owning team is disabled/blocked",
  "metadata": {
    "token_id": r.json.api_key_id,
    "api_key_disabled": r.json?.api_key_disabled,
    "api_key_blocked": r.json?.api_key_blocked,
    "team_blocked": r.json?.team_blocked
  }
} : r.status == 200 && type(r.json) == "map" && type(r.json?.api_key_id) == "string" && r.json.api_key_id != "" ? {
  "result": "valid",
  "analysis": {
    "user_id": string(r.json?.user_id ?? ""),
    "team_id": string(r.json?.team_id ?? ""),
    "token_id": string(r.json?.api_key_id ?? ""),
    "token_name": string(r.json?.name ?? ""),
    "acls": type(r.json?.acls) == "array" ? filter(r.json.acls, {type(#) == "string"}) : [],
    "created_at": string(r.json?.create_time ?? ""),
    "modified_at": string(r.json?.modify_time ?? ""),
    "api_key_disabled": r.json?.api_key_disabled,
    "api_key_blocked": r.json?.api_key_blocked,
    "team_blocked": r.json?.team_blocked
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const xaiAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {"id": input["user_id"] ?? "", "account": {"id": input["team_id"] ?? ""}},
  "metadata": {
    "token_id": input["token_id"] ?? "", "token_name": input["token_name"] ?? "",
    "acls": input["acls"] ?? [], "created_at": input["created_at"] ?? "", "modified_at": input["modified_at"] ?? "",
    "api_key_disabled": input["api_key_disabled"] ?? nil, "api_key_blocked": input["api_key_blocked"] ?? nil, "team_blocked": input["team_blocked"] ?? nil
  },
  "capabilities": [],
  "reason": "xAI model and endpoint ACLs do not establish resource read/write or administrative grants"
}`

func XAI() *config.Rule {
	r := config.Rule{
		ValidateExpr: xaiValidateExpr,
		AnalyzeExpr:  xaiAnalyzeExpr,
		ID:           "xai-api-key",
		Confidence:   "high",
		Description:  "Detected an xAI (Grok) API Key, which may expose Grok AI model access to unauthorized parties.",
		Regex:        utils.GenerateUniqueTokenRegex(`xai-[A-Za-z0-9_-]{70,120}`, true),
		Keywords:     []string{"xai-"},
		FilterExpr:   `entropy(finding["secret"]) <= 3.5`,
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
