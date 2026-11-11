package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "ionic-personal-access-token",
	Confidence:  "high",
	Description: "Ionic personal access token.",
	Regex:       Token(`ion_[A-Za-z0-9]{42}`),
	Keywords:    []string{"ionic"},
	ValidateExpr: `let r = http.post("https://api.ionic.io/graphql", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json",
    "Content-Type": "application/json"
  }, "{\"query\":\"query ValidateToken { viewer { __typename } }\"}"); r.status == 200 && (r.body contains "\"data\":{\"viewer\":{\"__typename\":") ? {
    "result": "valid"
  } : r.status in [401, 403] || (r.body contains "\"Unauthorized\"") ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "IONIC_TOKEN=ion_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipm", "ion_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipm"),
		NoMatch("false positive 1", "IONIC_TOKEN=ion_short"),
	},
})
