package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func Prefect() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "prefect-api-token",
		Description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
		Regex:       utils2.GenerateUniqueTokenRegex(`pnu_[a-zA-Z0-9]{36}`, false),
		Entropy:     2,
		Keywords: []string{
			"pnu_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("api-token", "pnu_"+secrets.NewSecret(utils2.AlphaNumeric("36")))
	fps := []string{
		`PREFECT_API_KEY = "pnu_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`,
	}
	return utils2.Validate(r, tps, fps)
}
