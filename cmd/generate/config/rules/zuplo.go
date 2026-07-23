package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func ZuploConsumerAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "zuplo-consumer-api-key.1",
		Description: "Zuplo consumer API key.",
		Regex:       utils.GenerateUniqueTokenRegex(`zpka_[a-z0-9]{32}_[0-9a-f]{8}`, false),
		Keywords:    []string{"zpka_"},
		ValidateExpr: `let r = http.get("https://dev.zuplo.com/v1/who-am-i", {
    "Authorization": "Bearer " + finding["secret"],
    "x-api-key": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Authorization failed"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	// validate
	tps := []string{
		`ZUPLO_API_KEY=zpka_3e6c4f7d39954ca29353b7ab88589b64_de26cd55`,
		`ZUPLO_API_KEY=zpka_b3f94d8d3d4d4a6ea5c5b20d0a5bb407_18eb262b`,
	}
	fps := []string{
		`ZUPLO_API_KEY=zpka_short`,
		`ZUPLO_API_KEY=zpka_00000000000000000000000000000000_00000000`,
	}
	return utils.Validate(r, tps, fps)
}
