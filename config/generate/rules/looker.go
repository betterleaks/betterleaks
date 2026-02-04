package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func LookerClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-id",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"looker"}, utils2.AlphaNumeric("20"), true),
		Keywords:    []string{"looker"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("looker", secrets.NewSecret(utils2.AlphaNumeric("20")))
	return utils2.Validate(r, tps, nil)
}

func LookerClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-secret",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"looker"}, utils2.AlphaNumeric("24"), true),
		Keywords:    []string{"looker"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("looker", secrets.NewSecret(utils2.AlphaNumeric("24")))
	return utils2.Validate(r, tps, nil)
}
