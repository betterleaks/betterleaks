package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func TwitterAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
		RuleID:      "twitter-api-key",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitter"}, utils.AlphaNumeric("25"), true),
		Keywords:    []string{"twitter"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitter", secrets.NewSecretWithEntropy(utils.AlphaNumeric("25"), 3.0))
	return utils.Validate(r, tps, nil)
}

func TwitterAPISecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
		RuleID:      "twitter-api-secret",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitter"}, utils.AlphaNumeric("50"), true),
		Keywords:    []string{"twitter"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitter", secrets.NewSecretWithEntropy(utils.AlphaNumeric("50"), 3.5))
	return utils.Validate(r, tps, nil)
}

func TwitterBearerToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.",
		RuleID:      "twitter-bearer-token",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitter"}, "A{22}[a-zA-Z0-9%]{80,100}", true),

		Keywords: []string{"twitter"},
		Filter:   `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitter", secrets.NewSecretWithEntropy("A{22}[a-zA-Z0-9%]{80,100}", 3.0))
	return utils.Validate(r, tps, nil)
}

func TwitterAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
		RuleID:      "twitter-access-token",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitter"}, "[0-9]{15,25}-[a-zA-Z0-9]{20,40}", true),
		Keywords:    []string{"twitter"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitter", secrets.NewSecretWithEntropy("[0-9]{15,25}-[a-zA-Z0-9]{20,40}", 3.5))
	return utils.Validate(r, tps, nil)
}

func TwitterAccessSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
		RuleID:      "twitter-access-secret",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"twitter"}, utils.AlphaNumeric("45"), true),
		Keywords:    []string{"twitter"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("twitter", secrets.NewSecretWithEntropy(utils.AlphaNumeric("45"), 3.5))
	return utils.Validate(r, tps, nil)
}
