package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://launchdarkly.com/docs/api/other/identify-the-caller
// https://launchdarkly.com/docs/api/access-tokens/get-access-token
// https://launchdarkly.com/docs/api/custom-roles/get-custom-role
// https://launchdarkly.com/docs/api/account-members/get-account-member
// https://launchdarkly.com/docs/home/account/api#access-token-permissions
// https://launchdarkly.com/docs/home/account/roles/organization-roles
// https://launchdarkly.com/docs/home/account/roles/role-actions
// At most six enrichment GETs. Personal tokens are bounded by the member's
// current permissions; _member is only a summary and omits overriding roles.
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
let personal = input["service_token"] == false;
let memberID = input["member_id"] ?? "";
let inspectMember = personal && len(body) > 0 && memberID matches "^[a-zA-Z0-9_-]{1,128}$";
let mr = inspectMember ? http.get("https://app.launchdarkly.com/api/v2/members/" + memberID, headers) : {};
let owner = mr?.status == 200 && type(mr?.json) == "map" && mr.json?._id == memberID ? mr.json : {};
let memberRole = type(owner?.role) == "string" && type(owner?.customRoles) == "array" && len(owner.customRoles) == 0 ? owner.role : "";
let roleIDs = type(body?.customRoleIds) == "array" ? filter(body.customRoleIds, {type(#) == "string"}) : [];
let selected = take(uniq(filter(roleIDs, {# matches "^[a-zA-Z0-9_-]{1,128}$"})), inspectMember ? 4 : 5);
let roles = map(selected, {
  let roleID = #;
  let response = http.get("https://app.launchdarkly.com/api/v2/roles/" + roleID, headers);
  let role = response.status == 200 && type(response.json) == "map" && (response.json?.key == roleID || response.json?._id == roleID) && type(response.json?.policy) == "array" ? response.json : {};
  {"id": roleID, "key": type(role?.key) == "string" ? role.key : "", "retrieved": len(role) > 0,
    "name": type(role?.name) == "string" ? role.name : "",
    "base_permissions": type(role?.basePermissions) == "string" ? role.basePermissions : "",
    "policy": type(role?.policy) == "array" ? concat(role.policy, type(role?._presetStatements) == "array" ? role._presetStatements : []) : [],
    "complete": len(role) > 0 && (role?._presetStatements == nil || type(role._presetStatements) == "array")}
});
let inline = type(body?.inlineRole) == "array" ? body.inlineRole : [];
let policies = concat(inline, flatten(map(roles, {#.policy})));
let complete = len(body) > 0 && (body?.customRoleIds == nil || (type(body.customRoleIds) == "array" && all(body.customRoleIds, {type(#) == "string"}))) &&
  (body?.inlineRole == nil || type(body.inlineRole) == "array") && len(roles) == len(uniq(roleIDs)) && all(roles, {#.complete}) &&
  all(policies, {type(#) == "map" && #?.effect in ["allow", "deny"] &&
    all([#?.actions, #?.notActions, #?.resources, #?.notResources], {# == nil || (type(#) == "array" && all(#, {type(#) == "string"}))}) &&
    (len(#?.actions ?? []) > 0 || len(#?.notActions ?? []) > 0) && (len(#?.resources ?? []) > 0 || len(#?.notResources ?? []) > 0)});
let tokenRole = type(body?.role) == "string" && len(roleIDs) == 0 && len(inline) == 0 ? body.role : "";
let ranks = {"reader": 1, "writer": 2, "admin": 3, "owner": 3, "owner/admin": 3};
let memberRank = ranks[memberRole] ?? 0;
let rank = complete ? min(ranks[tokenRole] ?? 0, input["service_token"] == true ? 3 : memberRank) : 0;
// A deliberately small set of documented actions and resource forms. Ambiguous
// selectors, action patterns, and potentially overlapping denies cannot prove a grant.
let grants = complete && (input["service_token"] == true || memberRank == 3) ? filter([
  {"capability": "read", "actions": ["viewProject"], "resource": "^proj/[a-zA-Z0-9_*-]+$"},
  {"capability": "write", "actions": ["updateOn", "createFlag", "deleteFlag", "updateRules", "updateTargets"], "resource": "^proj/[a-zA-Z0-9_*-]+:env/[a-zA-Z0-9_*-]+:flag/[a-zA-Z0-9_*-]+$"},
  {"capability": "manage_users", "actions": ["updateRole", "updateCustomRole", "createMember", "deleteMember"], "resource": "^member/[a-zA-Z0-9_*-]+$"}
], {
  let grant = #;
  any(grant.actions, {
    let action = #;
    any(policies, {#.effect == "allow" && len(#?.notResources ?? []) == 0 &&
      (action in (#?.actions ?? []) || "*" in (#?.actions ?? [])) &&
      all(#?.notActions ?? [], {# matches "^[a-zA-Z]+$" && # != action}) &&
      any(#?.resources ?? [], {# == "*" || # matches grant.resource})}) &&
    none(policies, {#.effect == "deny" &&
      (len(#?.notActions ?? []) > 0 || any(#?.actions ?? [], {# == action || !(# matches "^[a-zA-Z]+$")}))})
  })
}) : [];
let capabilities = analysis.capabilities({
  "read": rank >= 1 || any(grants, {#.capability == "read"}),
  "write": rank >= 2 || any(grants, {#.capability == "write"}),
  "manage_users": rank >= 3 || any(grants, {#.capability == "manage_users"}),
  "admin": rank >= 3
});
let member = type(body?._member) == "map" && body._member?._id == input["member_id"] ? body._member : {};
{
  "identity": {"id": input["service_token"] == false ? input["member_id"] ?? "" : "",
    "email": input["service_token"] == false && type(member?.email) == "string" ? member.email : "",
    "account": {"id": input["account_id"] ?? ""}},
  "metadata": fromPairs(filter(toPairs({"token_id": tokenID, "token_name": input["token_name"] ?? "", "service_token": input["service_token"],
    "scopes": input["scopes"] ?? [],
    "role": type(body?.role) == "string" ? body.role : "", "custom_role_ids": roleIDs,
    "member_role": personal && memberRank > 0 && memberRank < (ranks[tokenRole] ?? 0) ? memberRole : "",
    "custom_roles": map(filter(roles, {#.retrieved}), {
      {"id": #.id, "key": #.key, "name": #.name, "base_permissions": #.base_permissions,
       "policy": map(filter(#.policy, {type(#) == "map"}), {
         {"effect": type(#?.effect) == "string" ? #.effect : "",
           "actions": type(#?.actions) == "array" ? filter(#.actions, {type(#) == "string"}) : [],
           "resources": type(#?.resources) == "array" ? filter(#.resources, {type(#) == "string"}) : [],
           "notActions": type(#?.notActions) == "array" ? filter(#.notActions, {type(#) == "string"}) : [],
           "notResources": type(#?.notResources) == "array" ? filter(#.notResources, {type(#) == "string"}) : []}
       })}
    }),
    "inline_policy": map(filter(inline, {type(#) == "map"}), {
      {"effect": type(#?.effect) == "string" ? #.effect : "",
       "actions": type(#?.actions) == "array" ? filter(#.actions, {type(#) == "string"}) : [],
       "resources": type(#?.resources) == "array" ? filter(#.resources, {type(#) == "string"}) : [],
       "notActions": type(#?.notActions) == "array" ? filter(#.notActions, {type(#) == "string"}) : [],
       "notResources": type(#?.notResources) == "array" ? filter(#.notResources, {type(#) == "string"}) : []}
    }),
    "notes": filter([
      !complete ? "Token permission details could not be fully retrieved or interpreted." : "",
      personal && memberRank == 0 ? "The member's effective permissions could not be established; custom and team roles were not evaluated." : "",
      complete && len(policies) > 0 && len(capabilities) == 0 ? "Custom policy permissions could not be mapped to supported capabilities." : ""
    ], {# != ""})}), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": capabilities
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
