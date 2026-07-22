package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ValTownAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "val-town-api-token.1",
		Description: "Val Town API token.",
		Regex:       utils.GenerateUniqueTokenRegex(`vtwn_[A-Za-z0-9_-]{20,80}`, false),
		Keywords:    []string{"vtwn_"},
		ValidateExpr: `let r = http.get("https://api.val.town/v1/me", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"id\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5
|| !filter.matchesAny(finding["secret"], ["^(?:[^0-9]*[0-9]){2}"])`,
	}

	// validate
	tps := []string{
		"VALTOWN_TOKEN=vtwn_12" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{30}`, 3.5),
	}
	fps := []string{
		`VALTOWN_TOKEN=vtwn_short`,
		`VALTOWN_TOKEN=vtwn_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf`,
	}
	return utils.Validate(r, tps, fps)
}
