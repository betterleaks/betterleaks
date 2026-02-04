package rules

import (
	"regexp"

	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func AirtableApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-api-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"airtable"}, utils2.AlphaNumeric("17"), true),
		Keywords:    []string{"airtable"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("airtable", secrets.NewSecret(utils2.AlphaNumeric("17")))
	return utils2.Validate(r, tps, nil)
}

func AirtablePersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-personnal-access-token",
		Regex:       regexp.MustCompile(`\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`),
		Keywords:    []string{"airtable"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("airtable", "pat"+secrets.NewSecret(utils2.AlphaNumeric("14")+"\\."+utils2.Hex("64")))
	return utils2.Validate(r, tps, nil)
}
