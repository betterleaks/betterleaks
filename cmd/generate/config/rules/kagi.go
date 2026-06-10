package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func KagiAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "kagi-api-key",
		Description: "Detected a Kagi API key, which may expose Kagi API usage.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"kagi"}, utils.AlphaNumericExtendedShort("11")+`\.`+utils.AlphaNumericExtendedShort("43"), true),
		Keywords:    []string{"kagi"},
		ValidateCEL: `cel.bind(r,
  http.get("https://kagi.com/api/v0/search?q=test", {
    "Authorization": "Bot " + finding["secret"]
  }),
  r.status == 200 && r.body.contains("\"data\":") && r.body.contains("\"results\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`KAGI_API_KEY='AQAAUPJ-iQc.yLFDzC5RRHzPNDThhulREdoG0Bn3PiZMwJ6yqC6uJLE'`,
	}
	return utils.Validate(r, tps, nil)
}
