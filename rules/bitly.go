package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://dev.bitly.com/api-reference/
const bitlyValidateExpr = `let r = http.get("https://api-ssl.bitly.com/v4/user", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
let primary_emails = type(r.json) == "map" && type(r.json?.emails) == "array" ? filter(r.json.emails, { type(#) == "map" && #.is_primary == true }) : [];
r.status == 200 && type(r.json) == "map" && (r.json?.login ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "username": string(r.json?.login ?? ""),
      "name": string(r.json?.name ?? ""),
      "email": len(primary_emails) == 1 ? string(primary_emails[0]?.email ?? "") : ""
    },
    "metadata": {
      "default_group": string(r.json?.default_group_guid ?? "")
    }
  },
  "metadata": {
    "login": string(r.json?.login ?? "")
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const bitlyAnalyzeExpr = identityOnlyAnalyzeExpr

var _ = Add(config.Rule{
	ID:           "bitly-access-token",
	Confidence:   "high",
	Description:  "Detected a Bitly access token, which may allow unauthorized access to Bitly account and link management APIs.",
	Regex:        `(?i)\bbitly(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\n\r]){0,32}?([a-f0-9]{40})\b`,
	Keywords:     []string{"bitly"},
	ValidateExpr: bitlyValidateExpr,
	AnalyzeExpr:  bitlyAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "bitly_token = 20e9817b9c5ddde1b0cec7622bfc557dbc823791", "20e9817b9c5ddde1b0cec7622bfc557dbc823791"),
		NoMatch("false positive 1", "token = 20e9817b9c5ddde1b0cec7622bfc557dbc823791"),
		NoMatch("false positive 2", "bitly_token = 20e9817b9c5ddde1b0cec7622bfc557dbc82379"),
	},
})
