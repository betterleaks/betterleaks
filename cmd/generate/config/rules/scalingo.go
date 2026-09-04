package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func ScalingoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleID:      "scalingo-api-token",
		Confidence:  "high",
		Regex:       utils.GenerateUniqueTokenRegex(`tk-us-[\w-]{48}`, false),
		Keywords:    []string{"tk-us-"},
		Filter:      `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("scalingo", "tk-us-"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("48"), 2))
	tps = append(tps,
		`scalingo_api_token = "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-"`, // betterleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
