package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// All access tokens can call whoami, including tokens without Video read access.
// https://www.mux.com/docs/api-reference/system/utilities/get-whoami
// https://www.mux.com/docs/core/make-api-requests
const muxValidateExpr = `let r = http.get("https://api.mux.com/system/v1/whoami", {
  "Authorization": "Basic " + base64.encode(bytes((components["mux-access-token-id.1"]?.secret ?? "") + ":" + finding["secret"])),
  "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};
let data = type(body?.data) == "map" ? body.data : {};
r.status == 200 && type(data?.organization_id) == "string" && data.organization_id != "" && type(data?.environment_id) == "string" && data.environment_id != "" && type(data?.permissions) == "array" && all(data.permissions, {type(#) == "string"}) ? {
  "result": "valid", "analysis": {
    "organization_id": data.organization_id,
    "organization_name": type(data?.organization_name) == "string" ? data.organization_name : "",
    "environment_id": data.environment_id,
    "environment_name": type(data?.environment_name) == "string" ? data.environment_name : "",
    "environment_type": type(data?.environment_type) == "string" ? data.environment_type : "",
    "token_name": type(data?.access_token_name) == "string" ? data.access_token_name : "",
    "permissions": data.permissions
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`

const muxAnalyzeExpr = `let input = validation.analysis;
let permissions = input["permissions"] ?? [];
let capabilities = analysis.capabilities({
  "read": any(permissions, {# in ["video:read", "data:read", "system:read", "robots:read"]}),
  "write": any(permissions, {# in ["video:write", "data:write", "system:write", "robots:write"]})
});
{
  "identity": {"account": {"id": input["organization_id"], "name": input["organization_name"] ?? ""}},
  "metadata": fromPairs(filter(toPairs({
    "environment_id": input["environment_id"],
    "environment_name": input["environment_name"] ?? "",
    "environment_type": input["environment_type"] ?? "",
    "token_name": input["token_name"] ?? "",
    "permissions": permissions
  }), {#[1] != nil && #[1] != "" && #[1] != []})),
  "capabilities": capabilities
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "mux-access-token-id.1",
	Confidence:  "medium",
	Description: "Mux access-token ID, used as a component of the Mux access-token-secret composite rule.",
	Regex: rulebuilder.Assignment(
		[]string{`mux[_.-]?(?:access[_.-]?)?token[_.-]?(?:id|identifier)`},
		`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	),
	Keywords:   []string{"mux"},
	SkipReport: true,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "MUX_TOKEN_ID=1f7b169c-846f-218a-b552-fa82fbf86758", "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.MatchComponent("true positive 2", `mux_access_token_id: "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.NoMatchComponent("false positive 1", "TOKEN_ID=1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.NoMatchComponent("false positive 2", "MUX_TOKEN_ID=00000000-0000-0000-0000-000000000000"),
		rulebuilder.NoMatchComponent("false positive 3", "MUX_TOKEN_ID=short"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "mux-access-token-secret.1",
	Confidence:  "high",
	Description: "Mux access-token secret, which may grant access to video, data, or system APIs when paired with its token ID.",
	Regex: rulebuilder.Assignment(
		[]string{`mux[_.-]?(?:access[_.-]?)?token[_.-]?(?:secret|private|key)`},
		`[A-Za-z0-9+/]{75}`,
	),
	Keywords: []string{"mux"},
	Components: []config.Component{
		{RuleID: "mux-access-token-id.1", Within: "5L"},
	},
	ValidateExpr: muxValidateExpr,
	AnalyzeExpr:  muxAnalyzeExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "MUX_TOKEN_SECRET=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqb\nMUX_TOKEN_ID=1f7b169c-846f-218a-b552-fa82fbf86758",
			Expect: []config.ExpectedFinding{
				{Secret: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqb", ComponentSets: []map[string]string{{"mux-access-token-id.1": "1f7b169c-846f-218a-b552-fa82fbf86758"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "mux_access_token_secret: \"VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqb\"\nMUX_TOKEN_ID=1f7b169c-846f-218a-b552-fa82fbf86758",
			Expect: []config.ExpectedFinding{
				{Secret: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqb", ComponentSets: []map[string]string{{"mux-access-token-id.1": "1f7b169c-846f-218a-b552-fa82fbf86758"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "TOKEN_SECRET=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqb"),
		rulebuilder.NoMatch("false positive 2", "MUX_TOKEN_SECRET=short"),
		rulebuilder.NoMatch("false positive 3", "MUX_TOKEN_SECRET=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	},
})
