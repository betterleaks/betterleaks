package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func SendInBlueAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendinblue-api-token",
		Description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
		Regex:       utils2.GenerateUniqueTokenRegex(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`, false),
		Entropy:     2,
		Keywords: []string{
			"xkeysib-",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("sendinblue", "xkeysib-"+secrets.NewSecret(utils2.Hex("64"))+"-"+secrets.NewSecret(utils2.AlphaNumeric("16")))
	return utils2.Validate(r, tps, nil)
}
