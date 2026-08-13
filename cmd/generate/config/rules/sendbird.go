package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SendbirdAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-token",
		Confidence:  "high",
		Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sendbird"}, utils.Hex("40"), true),

		Keywords: []string{
			"sendbird",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("sendbird", secrets.NewSecretWithEntropy(utils.Hex("40"), 3.3))
	return utils.Validate(r, tps, nil)
}

func SendbirdAccessID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendbird-access-id",
		Confidence:  "high",
		Description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sendbird"}, utils.Hex8_4_4_4_12(), true),

		Keywords: []string{
			"sendbird",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("sendbird", secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3.3))
	return utils.Validate(r, tps, nil)
}
