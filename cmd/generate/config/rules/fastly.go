package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FastlyAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
		RuleID:      "fastly-api-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"fastly"}, utils.AlphaNumericExtendedShort("32"), true),
		Entropy:     3.5,
		Keywords:    []string{"fastly"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.fastly.com/current_user", {
    "Fastly-Key": secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("fastly", secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("32"), 3.5))
	tps = append(tps, `Fastly token: fgsb3ef237afd6c1b9d91f81cdba64f3`)
	return utils.Validate(r, tps, nil)
}
