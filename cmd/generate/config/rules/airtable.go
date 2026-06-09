package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AirtableApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"airtable"}, utils.AlphaNumeric("17"), true),
		Keywords:    []string{"airtable"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("airtable", secrets.NewSecret(utils.AlphaNumeric("17")))
	return utils.Validate(r, tps, nil)
}

func AirtablePersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-personnal-access-token",
		Regex:       regexp.MustCompile(`\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`),
		Keywords:    []string{"airtable"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.airtable.com/v0/meta/whoami", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.3`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("airtable", "pat"+secrets.NewSecret(utils.AlphaNumeric("14")+"\\."+utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}

func AirtableOAuthToken() *config.Rule {
	r := config.Rule{
		Description: "Detected an Airtable OAuth token, which may allow unauthorized access to Airtable resources granted to an OAuth integration.",
		RuleID:      "airtable-oauth-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"airtable"}, `[A-Z0-9]+\.v1\.[A-Z0-9_-]+\.[a-f0-9]+`, true),
		Keywords:    []string{"airtable"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.airtable.com/v0/meta/whoami", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`airtable_oauth_token = "APP7F9K2M4P6Q8R1.v1.XYZ123_ABC-DEF456_GHI789.abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"`,
	}
	fps := []string{
		`airtable_oauth_token = "EXAMPLE.v2.XYZ123_ABC.abcdef123456"`,
		`oauth_token = "APP7F9K2M4P6Q8R1.v1.XYZ123_ABC-DEF456_GHI789.abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"`,
	}
	return utils.Validate(r, tps, fps)
}
