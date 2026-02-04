package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func ScalingoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleID:      "scalingo-api-token",
		Regex:       utils2.GenerateUniqueTokenRegex(`tk-us-[\w-]{48}`, false),
		Entropy:     2,
		Keywords:    []string{"tk-us-"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("scalingo", "tk-us-"+secrets.NewSecret(utils2.AlphaNumericExtendedShort("48")))
	tps = append(tps,
		`scalingo_api_token = "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-"`, // gitleaks:allow
	)
	return utils2.Validate(r, tps, nil)
}
