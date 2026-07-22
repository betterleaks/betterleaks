package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func UnkeyRootKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "unkey-root-key.1",
		Description: "Unkey administrative root key.",
		Regex:       utils.GenerateUniqueTokenRegex(`unkey_[A-Za-z0-9]{20,32}`, false),
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
		Filter: `filter.entropy(finding["secret"]) < 3.5
|| !filter.matchesAny(finding["secret"], ["[0-9]"])
|| !filter.matchesAny(finding["secret"], ["[A-Z]"])
|| !filter.matchesAny(finding["secret"], ["[a-z]"])`,
	}

	// validate
	tps := []string{
		"UNKEY_ROOT_KEY=unkey_3Za" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{21}`, 3.5),
	}
	fps := []string{
		`UNKEY_ROOT_KEY=unkey_short`,
		`UNKEY_ROOT_KEY=unkey_xxxxxxxxxxxxxxxxxxxxxxxx`,
		`UNKEY_API_KEY=key_KH1V87o2X2GW`,
	}
	return utils.Validate(r, tps, fps)
}
