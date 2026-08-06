package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ThunderstoreAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "thunderstore-api-token.1",
		Description: "Thunderstore API token.",
		Regex:       utils.GenerateUniqueTokenRegex(`tss_[A-Za-z0-9_-]{20,80}`, false),
		Keywords:    []string{"tss_"},
		ValidateExpr: `let r = http.get("https://thunderstore.io/api/experimental/current-user/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"username\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid Service Account token"
  } : validate.unknown(r)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5
|| !filter.matchesAny(finding["secret"], ["^(?:[^0-9]*[0-9]){2}"])`,
	}

	// validate
	tps := []string{
		"THUNDERSTORE_TOKEN=tss_12" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{30}`, 3.5),
	}
	fps := []string{
		`tss_short`,
		`tss_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEf`,
	}
	return utils.Validate(r, tps, fps)
}
