package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://elevenlabs.io/docs/api-reference/user/get
const elevenlabsValidateExpr = `let r = http.get("https://api.elevenlabs.io/v1/user", {
  "xi-api-key": finding["secret"], "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};

r.status == 200 && (type(body?.user_id) == "string" && body.user_id != "") ? {
  "result": "valid", "analysis": {
    "id": body.user_id,
    "workspace_id": type(body?.workspace_id) == "string" ? body?.workspace_id : ""
  }
} : r.status == 401 && type(body?.detail) == "map" && body.detail?.status == "invalid_api_key" ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`
const elevenlabsAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {
    "id": input["id"] ?? "",
    "account": {"id": input["workspace_id"] ?? ""}
  },
  "capabilities": []
}`

var _ = rulebuilder.Add(config.Rule{
	ID:           "elevenlabs-api-key",
	Confidence:   "high",
	Description:  "Detected an ElevenLabs API Key, which may expose AI voice synthesis services to unauthorized access.",
	Regex:        rulebuilder.Assignment([]string{"elevenlabs"}, `(?i)sk_[0-9a-f]{48}`),
	Keywords:     []string{"elevenlabs"},
	FilterExpr:   `entropy(finding["secret"]) <= 3.5`,
	ValidateExpr: elevenlabsValidateExpr,
	AnalyzeExpr:  elevenlabsAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `elevenlabsToken = "sk_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4"`, "sk_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4"),
		rulebuilder.NoMatch("Too short", "elevenlabs_key = sk_2a30e5a0d39d5f2c5f6a9d2f95cd0160"),
		rulebuilder.NoMatch("Wrong prefix", "elevenlabs_key = ak_2a30e5a0d39d5f2c5f6a9d2f95cd016049a6323985479bfd"),
	},
})
