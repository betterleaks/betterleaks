package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func IonicPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "ionic-personal-access-token",
		Description: "Ionic personal access token.",
		Regex:       utils.GenerateUniqueTokenRegex(`ion_[A-Za-z0-9]{42}`, false),
		Keywords:    []string{"ion_"},
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
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"IONIC_TOKEN=ion_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("42"), 3.5),
	}
	fps := []string{
		`IONIC_TOKEN=ion_short`,
	}
	return utils.Validate(r, tps, fps)
}
