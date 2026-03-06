package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ScalingoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleID:      "scalingo-api-token",
		Regex:       utils.GenerateUniqueTokenRegex(`tk-us-[\w-]{48}`, false),
		Entropy:     2,
		Keywords:    []string{"tk-us-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("scalingo", "tk-us-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("48"), 2))
	tps = append(tps,
		`scalingo_api_token = "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-"`, // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
