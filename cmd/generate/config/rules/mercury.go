package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MercuryProductionAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mercury-production-api-token",
		Description: "Mercury production API token.",
		Regex:       utils.GenerateUniqueTokenRegex(`secret-token:mercury_production_[a-z]{3,6}_[A-Za-z0-9]{40,50}_yrucrem`, false),
		Keywords:    []string{"mercury_production_"},
		ValidateExpr: `let r = http.get("https://api.mercury.com/api/v1/accounts", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"MERCURY_API_TOKEN=secret-token:mercury_production_wma_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("44"), 3.5) + "_yrucrem",
	}
	fps := []string{
		`MERCURY_API_TOKEN=mercury_production_wma_24SCp4G81X3yHL4Wq8FgzuaP9ye3VKf2mgTDctXyRg5HY_yrucrem`,
		`MERCURY_API_TOKEN=secret-token:mercury_production_wma_short_yrucrem`,
	}
	return utils.Validate(r, tps, fps)
}
