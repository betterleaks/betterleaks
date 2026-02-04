package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func BitBucketClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
		RuleID:      "bitbucket-client-id",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"bitbucket"}, utils2.AlphaNumeric("32"), true),
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("bitbucket", secrets.NewSecret(utils2.AlphaNumeric("32")))
	return utils2.Validate(r, tps, nil)
}

func BitBucketClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
		RuleID:      "bitbucket-client-secret",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"bitbucket"}, utils2.AlphaNumericExtended("64"), true),

		Keywords: []string{"bitbucket"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("bitbucket", secrets.NewSecret(utils2.AlphaNumeric("64")))
	return utils2.Validate(r, tps, nil)
}
