package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "anthropic-api-key",
	Confidence:  "high",
	Description: "Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access.",
	Regex:       rulebuilder.Token(`sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`),
	Keywords: []string{
		"sk-ant-api03",
	},
	ValidateExpr: `let r = http.get("https://api.anthropic.com/v1/models", {
    "x-api-key": finding["secret"],
    "anthropic-version": "2023-06-01"
  }); r.status == 200 && (r.body contains '"data"') && (r.body contains '"type"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("Valid API key example", "sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA", "sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA"),
		rulebuilder.Match("true positive 1", `anthropic_api_token = "sk-ant-api03-4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025diy14kz56coijonpywz2z4vn644cqy1AA"`, "sk-ant-api03-4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025diy14kz56coijonpywz2z4vn644cqy1AA"),
		rulebuilder.NoMatch("Too short key (missing characters)", "sk-ant-api03-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA"),
		rulebuilder.NoMatch("Wrong suffix", "sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB"),
		rulebuilder.NoMatch("Wrong prefix (admin key, not API key)", "sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "anthropic-admin-api-key",
	Confidence:  "high",
	Description: "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
	Regex:       rulebuilder.Token(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`),
	Keywords: []string{
		"sk-ant-admin01",
	},
	ValidateExpr: `let r = http.get("https://api.anthropic.com/v1/organizations/me", {
    "x-api-key": finding["secret"],
    "anthropic-version": "2023-06-01"
  }); r.status == 200 && (r.json?.id ?? "") != "" && (r.json?.type ?? "") == "organization" ? {
    "result": "valid",
    "metadata": {"organization": (r.json?.name ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("Valid admin key example", "sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA", "sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA"),
		rulebuilder.Match("true positive 1", `anthropic_api_token = "sk-ant-admin01-4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025diy14kz56coijonpywz2z4vn644cqy1AA"`, "sk-ant-admin01-4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025diy14kz56coijonpywz2z4vn644cqy1AA"),
		rulebuilder.NoMatch("Too short key (missing characters)", "sk-ant-admin01-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA"),
		rulebuilder.NoMatch("Wrong suffix", "sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB"),
		rulebuilder.NoMatch("Wrong prefix (API key, not admin key)", "sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA"),
	},
})

// Claude subscription sign-ins (claude setup-token, Claude Code login) issue
// OAuth tokens instead of API keys. There is no safe validation: refreshing
// would consume a refresh token, so these rules only detect.
var _ = rulebuilder.Add(config.Rule{
	ID:          "anthropic-oauth-access-token",
	Confidence:  "high",
	Description: "Found an Anthropic OAuth access token, which grants access to a Claude subscription and its usage.",
	Regex:       rulebuilder.Token(`sk-ant-oat01-[a-zA-Z0-9_\-]{80,}`),
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Keywords: []string{
		"sk-ant-oat01",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("access token", "sk-ant-oat01-XADrJFeThUHJTqwHDNLvCiV-qvPacq76ESwF6Fnh6yrdM0_XER-OjVIhNfxpEU_LemS0OZ6S5q0MHayZmDaZvpBFcdG9bAA", "sk-ant-oat01-XADrJFeThUHJTqwHDNLvCiV-qvPacq76ESwF6Fnh6yrdM0_XER-OjVIhNfxpEU_LemS0OZ6S5q0MHayZmDaZvpBFcdG9bAA"),
		rulebuilder.Match("env assignment", `CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-XADrJFeThUHJTqwHDNLvCiV-qvPacq76ESwF6Fnh6yrdM0_XER-OjVIhNfxpEU_LemS0OZ6S5q0MHayZmDaZvpBFcdG9bAA`, "sk-ant-oat01-XADrJFeThUHJTqwHDNLvCiV-qvPacq76ESwF6Fnh6yrdM0_XER-OjVIhNfxpEU_LemS0OZ6S5q0MHayZmDaZvpBFcdG9bAA"),
		rulebuilder.NoMatch("placeholder", "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-xxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("long placeholder", "CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("refresh token", "sk-ant-ort01-jP7r9KdPmnAHR7ED3qNFZCRhIAew3YXE8YdqIih9BClqehA8Ea2HfBVLJjwbbVuez-aEukga49C1DpDTqWga6ZvO3bjlbAA"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "anthropic-oauth-refresh-token",
	Confidence:  "high",
	Description: "Found an Anthropic OAuth refresh token, which can be used to mint new access tokens for a Claude subscription.",
	Regex:       rulebuilder.Token(`sk-ant-ort01-[a-zA-Z0-9_\-]{80,}`),
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Keywords: []string{
		"sk-ant-ort01",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("refresh token", `"refreshToken": "sk-ant-ort01-jP7r9KdPmnAHR7ED3qNFZCRhIAew3YXE8YdqIih9BClqehA8Ea2HfBVLJjwbbVuez-aEukga49C1DpDTqWga6ZvO3bjlbAA"`, "sk-ant-ort01-jP7r9KdPmnAHR7ED3qNFZCRhIAew3YXE8YdqIih9BClqehA8Ea2HfBVLJjwbbVuez-aEukga49C1DpDTqWga6ZvO3bjlbAA"),
		rulebuilder.NoMatch("placeholder", "sk-ant-ort01-..."),
		rulebuilder.NoMatch("long placeholder", "sk-ant-ort01-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("access token", "sk-ant-oat01-XADrJFeThUHJTqwHDNLvCiV-qvPacq76ESwF6Fnh6yrdM0_XER-OjVIhNfxpEU_LemS0OZ6S5q0MHayZmDaZvpBFcdG9bAA"),
	},
})
