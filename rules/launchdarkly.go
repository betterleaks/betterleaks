package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://launchdarkly.com/docs/api/other/identify-the-caller
// https://launchdarkly.com/docs/api/access-tokens/get-access-token
// https://launchdarkly.com/docs/api/custom-roles/get-custom-role
// One token-detail GET plus at most five custom-role GETs. No policy inference
// from a member role, partial custom policies, or endpoint-required permissions.
const launchdarklyValidateExpr = `let r = http.get("https://app.launchdarkly.com/api/v2/caller-identity", {
  "Authorization": finding["secret"], "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};
r.status == 200 && type(body?.accountId) == "string" && body.accountId != "" && type(body?.tokenId) == "string" && body.tokenId != "" ? {
  "result": "valid", "analysis": {
    "account_id": body.accountId, "token_id": body.tokenId,
    "member_id": type(body?.memberId) == "string" ? body.memberId : "",
    "token_name": type(body?.tokenName) == "string" ? body.tokenName : "",
    "service_token": type(body?.serviceToken) == "bool" ? body.serviceToken : nil,
    "scopes": type(body?.scopes) == "array" ? filter(body.scopes, {type(#) == "string"}) : []
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`
const launchdarklyAnalyzeExpr = `let input = validation.analysis;
let headers = {"Authorization": finding["secret"], "Accept": "application/json"};
let tokenID = input["token_id"] ?? "";
let r = tokenID matches "^[a-zA-Z0-9_-]{1,128}$" ? http.get("https://app.launchdarkly.com/api/v2/tokens/" + tokenID, headers) : {};
let body = r?.status == 200 && type(r?.json) == "map" && r.json?._id == tokenID ? r.json : {};
let roleIDs = type(body?.customRoleIds) == "array" ? filter(body.customRoleIds, {type(#) == "string"}) : [];
let selected = take(filter(roleIDs, {# matches "^[a-zA-Z0-9_-]{1,128}$"}), 5);
let roles = map(selected, {
  let roleID = #;
  let response = http.get("https://app.launchdarkly.com/api/v2/roles/" + roleID, headers);
  let role = response.status == 200 && type(response.json) == "map" && (response.json?.key == roleID || response.json?._id == roleID) && type(response.json?.policy) == "array" ? response.json : {};
  {"id": roleID, "key": type(role?.key) == "string" ? role.key : "", "retrieved": len(role) > 0,
    "base_permissions": type(role?.basePermissions) == "string" ? role.basePermissions : "",
    "policy": type(role?.policy) == "array" ? map(filter(role.policy, {type(#) == "map"}), {
      {"effect": type(#?.effect) == "string" ? #.effect : "",
       "actions": type(#?.actions) == "array" ? filter(#.actions, {type(#) == "string"}) : [],
       "resources": type(#?.resources) == "array" ? filter(#.resources, {type(#) == "string"}) : [],
       "notActions": type(#?.notActions) == "array" ? filter(#.notActions, {type(#) == "string"}) : [],
       "notResources": type(#?.notResources) == "array" ? filter(#.notResources, {type(#) == "string"}) : []}
    }) : []}
});
let member = type(body?._member) == "map" && body._member?._id == input["member_id"] ? body._member : {};
{
  "identity": {"id": input["service_token"] == false ? input["member_id"] ?? "" : "",
    "email": input["service_token"] == false && type(member?.email) == "string" ? member.email : "",
    "account": {"id": input["account_id"] ?? ""}},
  "metadata": fromPairs(filter(toPairs({"token_id": tokenID, "token_name": input["token_name"] ?? "", "service_token": input["service_token"],
    "scopes": input["scopes"] ?? [], "token_details_retrieved": len(body) > 0,
    "role": type(body?.role) == "string" ? body.role : "", "custom_role_ids": roleIDs,
    "custom_roles": roles,
    "inline_policy": type(body?.inlineRole) == "array" ? map(filter(body.inlineRole, {type(#) == "map"}), {
      {"effect": type(#?.effect) == "string" ? #.effect : "",
       "actions": type(#?.actions) == "array" ? filter(#.actions, {type(#) == "string"}) : [],
       "resources": type(#?.resources) == "array" ? filter(#.resources, {type(#) == "string"}) : [],
       "notActions": type(#?.notActions) == "array" ? filter(#.notActions, {type(#) == "string"}) : [],
       "notResources": type(#?.notResources) == "array" ? filter(#.notResources, {type(#) == "string"}) : []}
    }) : [],
    "custom_roles_complete": len(body) > 0 && len(roles) == len(roleIDs) && all(roles, {#.retrieved})}), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": []
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "launchdarkly-access-token",
	Confidence:  "high",
	Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
	Regex:       rulebuilder.Assignment([]string{"launchdarkly"}, `(?i)[a-z0-9=_\-]{40}`),
	Keywords: []string{
		"launchdarkly",
	},
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	ValidateExpr: launchdarklyValidateExpr,
	AnalyzeExpr:  launchdarklyAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `launchdarklyToken = "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"`, "ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc"),
	},
})
