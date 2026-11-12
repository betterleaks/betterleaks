package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://apidocs.harness.io/organization
// Keep the existing validation endpoint for both PATs and SATs. A successful
// organization list proves read access; a forbidden response does not.
const harnessValidateExpr = `let r = http.get("https://app.harness.io/v1/orgs?limit=1&page=1", {
  "Accept": "application/json",
  "x-api-key": finding["secret"]
}); r.status in [200, 403] ? {
  "result": "valid",
  "analysis": {
    "can_read": r.status == 200 && type(r.json) == "array"
  }
} : r.status == 401 ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`

// https://apidocs.harness.io/tag/User/#operation/getCurrentUserInfo
// The second token segment identifies the account. PATs can resolve their user
// profile; SATs must not be attributed to a user. The profile's admin flag and
// other account memberships do not establish this token's effective grants.
const harnessAnalyzeExpr = `let input = validation.analysis;
let parts = split(finding["secret"], ".");
let account_id = len(parts) == 4 ? parts[1] : "";
let is_pat = parts[0] == "pat";
let profile = is_pat ? (
  let r = http.get("https://app.harness.io/ng/api/user/currentUser", {
    "Accept": "application/json",
    "x-api-key": finding["secret"]
  });
  r.status == 200 && type(r.json) == "map" && r.json?.status == "SUCCESS" &&
    type(r.json?.data) == "map" && type(r.json.data?.uuid) == "string" && r.json.data.uuid != "" ? r.json.data : {}
) : {};
let accounts = type(profile?.accounts) == "array" ? profile.accounts : [];
let account = find(accounts, {type(#) == "map" && #?.uuid == account_id});
let can_read = input["can_read"] ?? false;
{
  "identity": {
    "id": profile?.uuid ?? "",
    "name": type(profile?.name) == "string" ? profile.name : "",
    "email": type(profile?.email) == "string" ? profile.email : "",
    "account": {
      "id": account_id,
      "name": type(account?.accountName) == "string" ? account.accountName : ""
    }
  },
  "metadata": {
    "token_type": is_pat ? "personal_access_token" : "service_account_token"
  },
  "capabilities": analysis.capabilities({"read": can_read}),
  "reason": is_pat && len(profile) == 0 ? "Harness user profile was unavailable; effective permissions were not returned" :
    can_read ? "Organization listing confirmed read access; other effective permissions were not returned" :
    "Harness did not return effective permissions"
}`

// Define rule for Harness Personal Access Token (PAT) and Service Account Token (SAT)
var _ = rulebuilder.Add(config.Rule{
	Description:  "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
	ID:           "harness-api-key",
	Confidence:   "high",
	Regex:        `(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[0-9a-f]{24}\.[a-zA-Z0-9]{20}`,
	Keywords:     []string{"pat.", "sat."},
	ValidateExpr: harnessValidateExpr,
	AnalyzeExpr:  harnessAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.4`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `harnessToken = "pat.WE6v05tg7Z5jXlNPAK_XEP.1f7b169c846f218ab552fa82.5fbbd6p84oe7ut4qrtte"`, "pat.WE6v05tg7Z5jXlNPAK_XEP.1f7b169c846f218ab552fa82.5fbbd6p84oe7ut4qrtte"),
		rulebuilder.Match("harness assignment 2", `harnessToken = "sat.WE6v05tg7Z5jXlNPAK_XEP.1f7b169c846f218ab552fa82.5fbbd6p84oe7ut4qrtte"`, "sat.WE6v05tg7Z5jXlNPAK_XEP.1f7b169c846f218ab552fa82.5fbbd6p84oe7ut4qrtte"),
		rulebuilder.Match("true positive 1", `HARNESS_TOKEN="pat.AbCdEfGhIjKlMnOpQrStUv.0123abcd4567ef890123abcd.ZyXwVuTsRqPoNmLkJiHg"`, "pat.AbCdEfGhIjKlMnOpQrStUv.0123abcd4567ef890123abcd.ZyXwVuTsRqPoNmLkJiHg"),
	},
})
