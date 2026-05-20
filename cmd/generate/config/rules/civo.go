package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Civo() *config.Rule {
	r := config.Rule{
		RuleID:      "civo-api-key",
		Description: "Detected a Civo Cloud API key, which may expose Kubernetes clusters and compute resources to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"civo"}, utils.AlphaNumeric("50"), true),
		Keywords:    []string{"civo"},
		Entropy:     3.5,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.civo.com/v2/instances", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("civo", secrets.NewSecretWithEntropy(utils.AlphaNumeric("50"), 3.5))
	fps := []string{
		// Low entropy
		`civo_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
	}
	return utils.Validate(r, tps, fps)
}
