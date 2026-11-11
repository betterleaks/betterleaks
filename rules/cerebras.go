package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "cerebras-api-key",
	Confidence:  "high",
	Description: "Identified a Cerebras AI API Key, which may expose AI inference services to unauthorized access.",
	Regex:       Token(`(?i)csk-[a-z0-9]{48}`),
	Keywords:    []string{"csk-"},
	ValidateExpr: `let r = http.get("https://api.cerebras.ai/v1/models", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.body contains '"object"') && (r.body contains '"data"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("cerebras assignment", `cerebrasToken = "csk-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rys"`, "csk-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rys"),
		NoMatch("Too short", "csk-6nptf4w5cx36fw58t3hkx"),
		NoMatch("Wrong prefix", "bsk-6nptf4w5cx36fw58t3hkx48jvm52wm693pex5tjm29kn55yt"),
	},
})
