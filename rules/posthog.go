package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// Current-token metadata avoids the user:read requirement of users/@me.
// Keep explicit token boundaries, not the owner's last-opened UI organization.
// https://github.com/PostHog/posthog/blob/master/posthog/api/personal_api_key.py
// https://posthog.com/docs/api/scopes
const posthogPersonalValidateExpr = `let headers = {"Authorization": "Bearer " + finding["secret"], "Accept": "application/json"};
let path = "/api/personal_api_keys/@current/";
let us = http.get("https://us.posthog.com" + path, headers);
let useUS = us.status == 200 && type(us.json) == "map" && type(us.json?.id) in ["string", "float"] && us.json.id != "" && type(us.json?.user_id) in ["string", "float"] && us.json.user_id != "" && type(us.json?.scopes) == "array" && all(us.json.scopes, {type(#) == "string"});
let r = useUS ? us : http.get("https://eu.posthog.com" + path, headers);
let body = type(r.json) == "map" ? r.json : {};
let keyID = type(body?.id) == "string" ? body.id : type(body?.id) == "float" ? string(int(body.id)) : "";
let userID = type(body?.user_id) == "string" ? body.user_id : type(body?.user_id) == "float" ? string(int(body.user_id)) : "";
r.status == 200 && keyID != "" && userID != "" && type(body?.scopes) == "array" && all(body.scopes, {type(#) == "string"}) ? {
  "result": "valid", "analysis": {
    "region": useUS ? "us" : "eu", "key_id": keyID, "user_id": userID,
    "scopes": filter(body.scopes, {type(#) == "string"}),
    "scoped_teams": type(body?.scoped_teams) == "array" ? filter(body.scoped_teams, {type(#) in ["string", "float"]}) : [],
    "scoped_organizations": type(body?.scoped_organizations) == "array" ? filter(body.scoped_organizations, {type(#) == "string"}) : [],
    "expires_at": type(body?.expires_at) == "string" ? body.expires_at : nil
  }
} : us.status == 401 && r.status == 401 ? {"result": "invalid", "reason": "Unauthorized in both regions"} : validate.unknown(r)`
const posthogPersonalAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
let resources = ["action", "annotation", "cohort", "dashboard", "event", "experiment", "feature_flag", "insight", "organization", "organization_member", "person", "project", "query", "session_recording", "survey"];
let capabilities = analysis.capabilities({
  "read": any(resources, {let resource = #; resource + ":read" in scopes || resource + ":write" in scopes}),
  "write": any(resources, {# + ":write" in scopes}),
  "manage_users": "organization_member:write" in scopes
});
{
  "identity": {"id": input["user_id"] ?? ""},
  "metadata": fromPairs(filter(toPairs({"key_id": input["key_id"] ?? "", "region": input["region"] ?? "", "scopes": scopes,
    "scoped_teams": input["scoped_teams"] ?? [], "scoped_organizations": input["scoped_organizations"] ?? [], "expires_at": input["expires_at"]}), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": capabilities
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "posthog-personal-api-key",
	Confidence:  "high",
	Description: "Detected a PostHog Personal API Key, which may expose administrative access to PostHog analytics projects.",
	// "phx_" + a random token. The encoding has changed over time, so the body
	// length varies across keys still in the wild:
	//   - base62(32 bytes)          → 41-43 chars (2021 .. 2024, before #22362)
	//   - base62(35 bytes)          → 45-48 chars (2024 .. early 2026, mostly 47)
	//   - base57(35 bytes), top-bit → 48-49 chars (current, since #52495)
	Regex:      rulebuilder.Token(`(?i)phx_[a-zA-Z0-9_\-]{41,49}`),
	Keywords:   []string{"phx_"},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	// Keys are region-bound: an unverified US response falls back to EU.
	// Both regions must reject authentication before reporting invalid.
	ValidateExpr: posthogPersonalValidateExpr,
	AnalyzeExpr:  posthogPersonalAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `posthogToken = "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZz"`, "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZz"),
		rulebuilder.Match("bare secret", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHC", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHC"),
		rulebuilder.Match("bare secret 2", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		rulebuilder.Match("bare secret 3", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lIT", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lIT"),
		rulebuilder.Match("bare secret 4", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"),
		rulebuilder.NoMatch("too short", "phx_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.NoMatch("too long", "phx_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl1"),
		rulebuilder.NoMatch("Wrong prefix", "phy_FNKCx83Ko0JQMuZH1zz94xgK798TCUybkf79ZKYKwKQWbEw"),
	},
})
