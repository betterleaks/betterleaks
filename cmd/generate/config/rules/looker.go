package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func LookerClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-id",
		Confidence:  "medium",
		Regex:       utils.GenerateSemiGenericRegex([]string{"looker"}, utils.AlphaNumeric("20"), true),
		Keywords:    []string{"looker"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("looker", secrets.NewSecretWithEntropy(utils.AlphaNumeric("20"), 3.0))
	return utils.Validate(r, tps, nil)
}

func LookerClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-secret",
		Confidence:  "medium",
		Regex:       utils.GenerateSemiGenericRegex([]string{"looker"}, utils.AlphaNumeric("24"), true),
		Keywords:    []string{"looker"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("looker", secrets.NewSecretWithEntropy(utils.AlphaNumeric("24"), 3.0))
	return utils.Validate(r, tps, nil)
}
