package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://github.com/vultr/govultr/blob/master/account.go
// https://docs.vultr.com/reference/terraform/resources/user
// https://docs.vultr.com/support/platform/users/what-permissions-can-be-granted-to-users
const vultrValidateExpr = `let r = http.get("https://api.vultr.com/v2/account", {
  "Authorization": "Bearer " + finding["secret"], "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};
let account = type(body?.account) == "map" ? body.account : {};
r.status == 200 && type(account?.email) == "string" && account.email != "" ? {
  "result": "valid", "analysis": {
    "email": account.email,
    "name": type(account?.name) == "string" ? account.name : "",
    "acls": type(account?.acls) == "array" ? filter(account.acls, {type(#) == "string"}) : []
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`
const vultrAnalyzeExpr = `let input = validation.analysis;
let acls = input["acls"] ?? [];
let capabilities = analysis.capabilities({
  "read": any(acls, {# in ["subscriptions_view", "subscriptions", "billing"]}),
  "write": any(acls, {# in ["provisioning", "dns", "upgrade", "objstore", "loadbalancer"]}),
  "manage_users": "manage_users" in acls
});
{
  "identity": {"name": input["name"] ?? "", "email": input["email"] ?? ""},
  "metadata": fromPairs(filter(toPairs({"acls": acls}), {#[1] != nil && #[1] != "" && #[1] != []})), "capabilities": capabilities
}`

var _ = rulebuilder.Add(config.Rule{
	ID:           "vultr-api-key.1",
	Confidence:   "medium",
	Description:  "Vultr API key, which may allow management of cloud account resources.",
	Regex:        rulebuilder.Assignment([]string{"vultr"}, `(?i)[a-f0-9]{36}`),
	Keywords:     []string{"vultr"},
	ValidateExpr: vultrValidateExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.4),
	AnalyzeExpr:  vultrAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "VULTR_API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c", "1f7b169c846f218ab552fa82fbf86758bf5c"),
		rulebuilder.Match("true positive 2", `vultr token: "1f7b169c846f218ab552fa82fbf86758bf5c"`, "1f7b169c846f218ab552fa82fbf86758bf5c"),
		rulebuilder.NoMatch("false positive 1", "API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c"),
		rulebuilder.NoMatch("false positive 2", "VULTR_API_KEY=short"),
		rulebuilder.NoMatch("false positive 3", "VULTR_API_KEY=000000000000000000000000000000000000"),
	},
})
