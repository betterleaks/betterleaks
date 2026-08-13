package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func NewRelicUserID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-key",
		Confidence:  "high",
		Description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRAK-[a-z0-9]{27}`, true),

		Keywords: []string{
			"NRAK",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", "NRAK-"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("27"), 3.5))
	return utils.Validate(r, tps, nil)
}

func NewRelicUserKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-user-api-id",
		Confidence:  "high",
		Description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, utils.AlphaNumeric("64"), true),

		Keywords: []string{
			"new-relic",
			"newrelic",
			"new_relic",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 3.5))
	return utils.Validate(r, tps, nil)
}

func NewRelicBrowserAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-browser-api-token",
		Confidence:  "high",
		Description: "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRJS-[a-f0-9]{19}`, true),

		Keywords: []string{
			"NRJS-",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", "NRJS-"+secrets.NewSecretWithEntropy(utils.Hex("19"), 3.0))
	return utils.Validate(r, tps, nil)
}

func NewRelicInsertKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "new-relic-insert-key",
		Confidence:  "high",
		Description: "Discovered a New Relic insight insert key, compromising data injection into the platform.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"new-relic",
			"newrelic",
			"new_relic",
		}, `NRII-[a-z0-9-]{32}`, true),

		Keywords: []string{
			"NRII-",
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("new-relic", "NRII-"+secrets.NewSecretWithEntropy(utils.Hex("32"), 3.5))
	return utils.Validate(r, tps, nil)
}
