package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://docs.honeycomb.io/api/auth/list-authorizations
const honeycombValidateExpr = `let r = http.get("https://api.honeycomb.io/1/auth", {
  "X-Honeycomb-Team": finding["secret"],
  "Accept": "application/json"
}); r.status == 200 && r.json?.team != nil ? {
  "result": "valid",
  "analysis": {
    "key_id": r.json?.id ?? "",
    "key_type": r.json?.type ?? "",
    "permissions": r.json?.api_key_access ?? {},
    "team_name": r.json?.team?.name ?? "",
    "team_slug": r.json?.team?.slug ?? "",
    "environment_name": r.json?.environment?.name ?? "",
    "environment_slug": r.json?.environment?.slug ?? ""
  }
} : r.status in [401, 403] ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`

// The auth API's "queries" grant runs queries; "columns" manages query
// definitions. Ingestion and configuration writes do not imply query access.
// https://docs.honeycomb.io/configure/environments/manage-api-keys
// https://github.com/honeycombio/terraform-provider-honeycombio/blob/main/docs/data-sources/auth_metadata.md
const honeycombAnalyzeExpr = `let input = validation.analysis;
let permissions = input["permissions"] ?? {};
let can_read = (permissions["queries"] ?? false) == true;
let can_write = any([
  "events", "markers", "triggers", "boards", "columns", "createDatasets", "slos", "recipients", "privateBoards"
], {(permissions[#] ?? false) == true});
{
  "reason": len(permissions) == 0 ? "Honeycomb did not return API key permission metadata" :
    !can_read && !can_write ? "Honeycomb returned no recognized enabled permissions" : "",
  "identity": {
    "account": {
      "id": input["team_slug"] ?? "",
      "name": input["team_name"] ?? ""
    }
  },
  "metadata": {
    "key_id": input["key_id"] ?? "",
    "key_type": input["key_type"] ?? "",
    "permissions": permissions,
    "environment_name": input["environment_name"] ?? "",
    "environment_slug": input["environment_slug"] ?? ""
  },
  "capabilities": analysis.capabilities({"read": can_read, "write": can_write})
}`

var _ = rulebuilder.Add(config.Rule{
	ID:           "honeycomb-api-key",
	Confidence:   "medium",
	Description:  "Detected a Honeycomb API key, which may expose Honeycomb telemetry and environment data.",
	Regex:        rulebuilder.Assignment([]string{"honeycomb"}, `(?i)(?:[a-f0-9]{32}|[a-z0-9]{22})`),
	Keywords:     []string{"honeycomb"},
	ValidateExpr: honeycombValidateExpr,
	AnalyzeExpr:  honeycombAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "honeycomb_secret_key=8f14e45fceea167a5a36dedd4bea2543", "8f14e45fceea167a5a36dedd4bea2543"),
		rulebuilder.Match("true positive 2", "honeycomb_token=z0d1f2bcaloumn3456789P", "z0d1f2bcaloumn3456789P"),
	},
})
