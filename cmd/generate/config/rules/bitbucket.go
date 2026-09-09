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
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("bitbucket", secrets.NewSecretWithEntropy(utils.AlphaNumeric("32"), 3.5))
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
		Filter:   `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("bitbucket", secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 3.5))
	return utils.Validate(r, tps, nil)
}

func BitBucketDataCenterToken() *config.Rule {
	// BBDC- prefix, then base64 of "<token id>:<random bytes>"
	r := config.Rule{
		Description: "Discovered a Bitbucket Data Center HTTP access token, risking unauthorized repository and project access.",
		RuleID:      "bitbucket-data-center-token",
		Confidence:  "high",
		Regex:       utils.GenerateUniqueTokenRegex(`BBDC-[A-Za-z0-9+/=]{32,}`, false),
		Keywords:    []string{"bbdc"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := []string{
		`BITBUCKET_TOKEN = "BBDC-` + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/=]{44}`, 3.5) + `"`,
		`token=BBDC-` + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/=]{60}`, 3.5),
		`BBDC-ODU3MDkzMTU4MDk1OiKqsM8HOsW1XhaMu33mVB6bLJea`,
	}

	fps := []string{
		`BITBUCKET_TOKEN = "BBDC-` + secrets.NewSecret(`[A-Za-z0-9+/=]{20}`) + `"`,
		`bbdc-config-name = "staging"`,
	}

	return utils.Validate(r, tps, fps)
}
