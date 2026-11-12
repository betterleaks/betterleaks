package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "lichess-personal-access-token",
	Confidence:  "high",
	Description: "Lichess personal access token.",
	Regex:       rulebuilder.Token(`lip_[A-Za-z0-9_]{16,60}`),
	Keywords:    []string{"lip_"},
	ValidateExpr: `let r = http.get("https://lichess.org/api/account", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid",
    "metadata": {"username": (r.json?.username ?? "")}
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "LICHESS_TOKEN=lip_eoTtDxpQ4FWYcbMq0Kt5b9ws_pgsxUmO", "lip_eoTtDxpQ4FWYcbMq0Kt5b9ws_pgsxUmO"),
		rulebuilder.NoMatch("false positive 1", "LICHESS_TOKEN=lip_short"),
	},
})
