package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func RainforestPayProductionAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "rainforest-pay-production-api-key",
		Description: "Rainforest Pay production API key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`rainforest(?:[_. -]*pay)?(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`apikey_[a-f0-9]{64}`,
			false,
		),
		Keywords: []string{"rainforest"},
		ValidateExpr: `let r = http.get("https://api.rainforestpay.com/v1/merchants?limit=1", {
    "Authorization": "Bearer " + finding["secret"],
    "Rainforest-Api-Version": "2024-10-16",
    "Accept": "application/json"
  }); r.status == 200 && (r.json?.status ?? "") == "SUCCESS" ? {
    "result": "valid"
  } : r.status == 403 && (r.json?.status ?? "") == "ERROR" ? {
    "result": "valid",
    "reason": "Authenticated but merchant access is restricted"
  } : r.status == 401 && (r.json?.status ?? "") == "ERROR" ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"RAINFOREST_API_KEY=apikey_" + secrets.NewSecretWithEntropy(`[a-f0-9]{64}`, 3.5),
	}
	fps := []string{
		`RAINFOREST_API_KEY=sbx_apikey_2bd2c646e7e1194f8c9cf194e8f4555de1f3eefbbc472003276666d4efb76e74`,
		`API_KEY=apikey_1ad1c535b0c0093e7b9bf093d7e3444cd0e2ddefab36199216f555c3efa65d63`,
		`RAINFOREST_API_KEY=apikey_0000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
