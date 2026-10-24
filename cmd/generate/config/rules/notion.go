package rules

import (
	"strings"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://developers.notion.com/reference/get-self
// https://developers.notion.com/reference/status-codes
const notionValidateExpr = `let r = http.get("https://api.notion.com/v1/users/me", {
  "Authorization": "Bearer " + finding["secret"],
  "Notion-Version": "2026-03-11"
});
r.status == 200 && type(r.json) == "map" && r.json?.object == "user" && type(r.json?.id) == "string" && r.json.id != "" ? (
  let bot = type(r.json?.bot) == "map" ? r.json.bot : {};
  let owner = type(bot?.owner) == "map" ? bot.owner : {};
  let user = owner?.type == "user" && type(owner?.user) == "map" ? owner.user : {};
  {
    "result": "valid",
    "analysis": {
      "identity": {
        "id": user?.id ?? r.json.id,
        "name": user?.name ?? r.json?.name ?? "",
        "email": user?.person?.email ?? "",
        "account": {"id": bot?.workspace_id ?? "", "name": bot?.workspace_name ?? ""}
      },
      "metadata": {
        "bot_id": r.json.id,
        "bot_name": r.json?.name ?? "",
        "owner_type": owner?.type ?? ""
      }
    }
  }
) : r.status == 401 && type(r.json) == "map" && r.json?.code == "unauthorized" ? {
  "result": "invalid", "reason": "Notion rejected the API token"
} : validate.unknown(r)`

func Notion() *config.Rule {
	r := config.Rule{
		ID:           "notion-api-token",
		Description:  "Notion API token",
		Confidence:   "high",
		Regex:        `\b(ntn_[A-Za-z0-9]{46})\b`,
		Keywords:     []string{"ntn_"},
		FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
		ValidateExpr: notionValidateExpr,
		AnalyzeExpr:  identityOnlyAnalyzeExpr,
	}

	token := "ntn_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{46}`, 4.5)
	tps := utils.GenerateSampleSecrets("notion", token)
	fps := []string{"ntn_12345678901", "ntn_" + strings.Repeat("x", 46), "development_" + token, token + token, token + "NOTION_DATABASE_ID=placeholder"}
	return utils.Validate(r, tps, fps)
}

func NotionLegacyAPIToken() *config.Rule {
	r := config.Rule{
		ID:           "notion-api-token-legacy",
		Description:  "Notion API token (legacy)",
		Confidence:   "medium",
		Regex:        `\b(secret_[A-Za-z0-9]{43})\b`,
		Keywords:     []string{"secret_"},
		FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
		ValidateExpr: notionValidateExpr,
		AnalyzeExpr:  identityOnlyAnalyzeExpr,
	}

	token := "secret_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{43}`, 4.5)
	tps := utils.GenerateSampleSecrets("notion", token)
	fps := []string{token + "extra", "client_" + token, token[:len(token)-1], "secret_" + strings.Repeat("x", 43)}
	return utils.Validate(r, tps, fps)
}
