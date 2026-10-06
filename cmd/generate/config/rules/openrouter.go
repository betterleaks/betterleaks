package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://openrouter.ai/docs/api/api-reference/api-keys/get-current-key
// https://openrouter.ai/docs/api/api-reference/api-keys/create-keys
// https://openrouter.ai/docs/guides/features/workspaces/overview
// Do not retain label: it can contain part of the submitted secret.
const openrouterValidateExpr = `let r = http.get("https://openrouter.ai/api/v1/key", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && type(r.json?.data?.label) == "string" ? {
  "result": "valid",
  "analysis": {
    "creator_user_id": string(r.json?.data?.creator_user_id ?? ""),
    "organization_id": string(r.json?.data?.organization_id ?? ""),
    "workspace_id": string(r.json?.data?.workspace_id ?? ""),
    "expires_at": r.json?.data?.expires_at,
    "is_management_key": r.json?.data?.is_management_key
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const openrouterAnalyzeExpr = `let input = validation.analysis;
let management = input["is_management_key"] == true;
let accountID = (input["organization_id"] ?? "") != "" ? input["organization_id"] : (input["workspace_id"] ?? "");
{
  "identity": {"id": input["creator_user_id"] ?? "", "account": {"id": accountID}},
  "metadata": {"expires_at": input["expires_at"] ?? nil},
  "capabilities": analysis.capabilities({"create_credentials": management}),
  "reason": management ? "" : "OpenRouter did not return effective permissions for this key"
}`

func OpenRouter() *config.Rule {
	r := config.Rule{
		ValidateExpr: openrouterValidateExpr,
		AnalyzeExpr:  openrouterAnalyzeExpr,
		ID:           "openrouter-api-key",
		Confidence:   "high",
		Description:  "Detected an OpenRouter API Key, which may expose access to multiple AI models through the OpenRouter gateway.",
		Regex:        utils.GenerateUniqueTokenRegex(`sk-or-v1-[0-9a-f]{64}`, true),
		Keywords:     []string{"sk-or-v1-"},
		FilterExpr:   `entropy(finding["secret"]) <= 3.5`,
	}

	tps := utils.GenerateSampleSecrets("openrouter", "sk-or-v1-"+secrets.NewSecretWithEntropy(utils.Hex("64"), 3.5))
	fps := []string{
		// Too short
		`sk-or-v1-0e6f44a47a05f1dad2ad7e88c4c1d6b7`,
		// Wrong prefix
		`sk-v1-0e6f44a47a05f1dad2ad7e88c4c1d6b77688157716fb1a5271146f7464951c96`,
	}
	return utils.Validate(r, tps, fps)
}
