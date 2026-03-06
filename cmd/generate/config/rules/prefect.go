package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Prefect() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "prefect-api-token",
		Description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
		Regex:       utils.GenerateUniqueTokenRegex(`pnu_[a-zA-Z0-9]{36}`, false),
		Entropy:     2,
		Keywords: []string{
			"pnu_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("api-token", "pnu_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 2))
	fps := []string{
		`PREFECT_API_KEY = "pnu_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`,
	}
	return utils.Validate(r, tps, fps)
}
