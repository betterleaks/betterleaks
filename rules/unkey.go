package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "unkey-root-key.1",
	Confidence:  "high",
	Description: "Unkey administrative root key.",
	Regex:       rulebuilder.Token(`unkey_[A-Za-z0-9]{20,32}`),
	Keywords:    []string{"unkey_"},
	ValidateExpr: `let r = http.post("https://api.unkey.com/v2/keys.verifyKey", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"key\":\"betterleaks_validation_key\"}"); r.status == 200 && (r.body contains "\"data\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid root key"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5
|| !matchesAny(finding["secret"], ["[0-9]"])
|| !matchesAny(finding["secret"], ["[A-Z]"])
|| !matchesAny(finding["secret"], ["[a-z]"])`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "UNKEY_ROOT_KEY=unkey_3ZaRFbD56TI2smTyVsGd5Xav", "unkey_3ZaRFbD56TI2smTyVsGd5Xav"),
		rulebuilder.NoMatch("false positive 1", "UNKEY_ROOT_KEY=unkey_short"),
		rulebuilder.NoMatch("false positive 2", "UNKEY_ROOT_KEY=unkey_xxxxxxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("false positive 3", "UNKEY_API_KEY=key_KH1V87o2X2GW"),
	},
})
