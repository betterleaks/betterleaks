package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://wakatime.com/developers#users
const wakaTimeAPIKeyValidateExpr = `let r = http.get("https://api.wakatime.com/api/v1/users/current?api_key=" + finding["secret"], {"Accept": "application/json"});
r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && (r.json?.data?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.data?.id ?? ""),
      "username": string(r.json?.data?.username ?? ""),
      "name": string(r.json?.data?.display_name ?? ""),
      "email": string(r.json?.data?.email ?? "")
    },
    "metadata": {}
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const wakaTimeAPIKeyAnalyzeExpr = identityOnlyAnalyzeExpr

var _ = Add(config.Rule{
	ID:          "wakatime-api-key.1",
	Confidence:  "high",
	Description: "WakaTime API key version 1 (UUID format).",
	Regex: Assignment(
		[]string{`waka[_. -]?time(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	),
	Keywords:     []string{"wakatime", "waka_time", "waka-time", "waka time", "waka.time"},
	ValidateExpr: wakaTimeAPIKeyValidateExpr,
	AnalyzeExpr:  wakaTimeAPIKeyAnalyzeExpr,
	FilterExpr:   MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("true positive 1", "WAKATIME_API_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		Match("true positive 2", `waka_time_api_key: "d4e5f6a7-b8c9-0123-4567-89abcdef0123"`, "d4e5f6a7-b8c9-0123-4567-89abcdef0123"),
		NoMatch("false positive 1", "API_KEY=a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
		NoMatch("false positive 2", "WAKATIME_API_KEY=00000000-0000-0000-0000-000000000000"),
	},
})

var _ = Add(config.Rule{
	ID:           "wakatime-api-key.2",
	Confidence:   "high",
	Description:  "WakaTime API key version 2 (waka_ format).",
	Regex:        Token(`(?i)waka_[a-z0-9]{36,64}`),
	Keywords:     []string{"waka_"},
	ValidateExpr: wakaTimeAPIKeyValidateExpr,
	AnalyzeExpr:  wakaTimeAPIKeyAnalyzeExpr,
	FilterExpr:   MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("true positive 1", "WAKATIME_API_KEY=waka_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li", "waka_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li"),
		NoMatch("false positive 1", "WAKATIME_API_KEY=waka_short"),
		NoMatch("false positive 2", "WAKATIME_API_KEY=waka_0000000000000000000000000000000000000000"),
	},
})
