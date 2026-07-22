package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SamsaraAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "samsara-api-token.1",
		Description: "Samsara API token.",
		Regex:       utils.GenerateUniqueTokenRegex(`samsara_api_[A-Za-z0-9]{26,32}`, false),
		Keywords:    []string{"samsara_api_"},
		ValidateExpr: `let r = http.get("https://api.samsara.com/fleet/vehicles", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but vehicle access is restricted"
  } : r.status == 401 && (r.json?.message ?? "") == "invalid token" ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"SAMSARA_API_TOKEN=samsara_api_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("30"), 3.0),
	}
	fps := []string{
		`SAMSARA_API_TOKEN=samsara_api_short`,
		`SAMSARA_API_TOKEN=samsara_api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
