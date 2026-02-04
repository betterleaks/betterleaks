package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func SendbirdAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-token",
		Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"sendbird"}, utils2.Hex("40"), true),

		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("sendbird", secrets.NewSecret(utils2.Hex("40")))
	return utils2.Validate(r, tps, nil)
}

func SendbirdAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-id",
		Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"sendbird"}, utils2.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"sendbird",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("sendbird", secrets.NewSecret(utils2.Hex8_4_4_4_12()))
	return utils2.Validate(r, tps, nil)
}
