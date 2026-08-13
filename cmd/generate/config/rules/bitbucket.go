package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func BitBucketClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
		RuleID:      "bitbucket-client-id",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumeric("32"), true),
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bitbucket", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}

func BitBucketClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
		RuleID:      "bitbucket-client-secret",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"bitbucket"}, utils.AlphaNumericExtended("64"), true),

		Keywords: []string{"bitbucket"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bitbucket", secrets.NewSecret(utils.AlphaNumeric("64")))
	return utils.Validate(r, tps, nil)
}
