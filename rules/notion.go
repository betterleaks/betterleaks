package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://developers.notion.com/reference/get-self
// Bot workspace/owner fields: https://github.com/makenotion/notion-sdk-js/blob/main/src/api-endpoints/common.ts
const notionValidateExpr = `let r = http.get("https://api.notion.com/v1/users/me", {
  "Authorization": "Bearer " + finding["secret"], "Notion-Version": "2026-03-11", "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};
let bot = type(body?.bot) == "map" ? body.bot : {};
let owner = type(bot?.owner) == "map" ? bot.owner : {};
let user = type(owner?.user) == "map" ? owner.user : {};
r.status == 200 && (body?.object == "user" && body?.type == "bot" && type(body?.id) == "string" && body.id != "") ? {
  "result": "valid", "analysis": {
    "id": body.id,
    "name": type(body?.name) == "string" ? body?.name : "",
    "workspace_id": type(bot?.workspace_id) == "string" ? bot?.workspace_id : "",
    "workspace_name": type(bot?.workspace_name) == "string" ? bot?.workspace_name : "",
    "owner_id": type(user?.id) == "string" ? user?.id : ""
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`
const notionAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {
    "id": input["id"] ?? "",
    "name": input["name"] ?? "",
    "account": {"id": input["workspace_id"] ?? "", "name": input["workspace_name"] ?? ""}
  },
  "capabilities": [],
  "metadata": fromPairs(filter(toPairs({
    "owner_id": input["owner_id"] ?? ""
  }), {#[1] != nil && #[1] != "" && #[1] != []}))
}`

var _ = rulebuilder.Add(config.Rule{
	Description:  "Notion API token",
	ID:           "notion-api-token",
	Confidence:   "high",
	Regex:        rulebuilder.Token(`ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`),
	Keywords:     []string{"ntn_"},
	FilterExpr:   `entropy(finding["secret"]) <= 4.0`,
	ValidateExpr: notionValidateExpr,
	AnalyzeExpr:  notionAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("bare secret", "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", "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"),
		rulebuilder.Match("bare secret 2", "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", "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"),
		rulebuilder.Match("bare secret 3", "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", "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"),
		rulebuilder.NoMatch("false positive 1", "ntn_12345678901"),
		rulebuilder.NoMatch("false positive 2", "ntn_123456789012345678901234567890123456789012345678901234567890"),
		rulebuilder.NoMatch("false positive 3", "ntn_12345678901abc"),
	},
})
