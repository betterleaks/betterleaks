package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LookerClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-id",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"looker"}, utils.AlphaNumeric("20"), true),
		Keywords:    []string{"looker"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("looker", secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func LookerClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-secret",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"looker"}, utils.AlphaNumeric("24"), true),
		Keywords:    []string{"looker"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("looker", secrets.NewSecret(utils.AlphaNumeric("24")))
	return utils.Validate(r, tps, nil)
}
