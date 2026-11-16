package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "cal-api-key",
	Confidence:  "high",
	Description: "Detected a Cal.com API key, which may allow programmatic access to scheduling and booking APIs.",
	Regex:       rulebuilder.Token(`cal_live_[a-f0-9]{32}`),
	Keywords:    []string{"cal_live_"},
	ValidateExpr: `let r = http.get("https://api.cal.com/v2/me", {"Authorization": "Bearer " + finding["secret"], "User-Agent": "Go-http-client/1.1"});
(r.status in [200] && (r.json?.status == "success")) ? {
    "result": "valid",
    "analysis": {
      "account_id": string(r.json?.data?.id ?? ""),
      "username": string(r.json?.data?.username ?? ""),
    }
  } :
(r.status in [401]) ? {"result": "invalid"} :
validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("shape 1", `token = "cal_live_032f99b8ca5cd6a40e45a8590845c942"`, `cal_live_032f99b8ca5cd6a40e45a8590845c942`),
		rulebuilder.NoMatch("near miss 1", `token = "cal_live_4875f0ddbe9ac138959d8d71d7ec05f"`),
	},
})
