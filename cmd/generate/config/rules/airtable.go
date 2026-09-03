package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

const airtableValidateExpr = `let r = http.get("https://api.airtable.com/v0/meta/whoami", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 ? {
    "result": "valid",
    "id": (r.json?.id ?? ""),
    "email": (r.json?.email ?? ""),
    "scopes": (r.json?.scopes ?? [])
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

const airtableAnalyzeExpr = `let metadata = validation.metadata;
let scopes = metadata["scopes"] ?? [];
{
  "identity": {
    "id": metadata["id"] ?? "",
    "email": metadata["email"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": filter.matchesAny(scopes, [":read$"]),
    "write": filter.matchesAny(scopes, ["^(?:data[.]|schema[.]).*:write$", "^webhook:manage$"]),
    "manage_users": filter.matchesAny(scopes, ["^enterprise[.](?:user:write|groups:manage|scim[.]usersAndGroups:manage)$"])
  })
}`

func AirtableApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Airtable API Key, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:      "airtable-api-key",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"airtable"}, utils.AlphaNumeric("17"), true),
		Keywords:    []string{"airtable"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("airtable", secrets.NewSecretWithEntropy(utils.AlphaNumeric("17"), 3.0))
	return utils.Validate(r, tps, nil)
}

func AirtablePersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description:  "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
		RuleID:       "airtable-personnal-access-token",
		Confidence:   "high",
		Regex:        regexp.MustCompile(`\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`),
		Keywords:     []string{"airtable"},
		ValidateExpr: airtableValidateExpr,
		AnalyzeExpr:  airtableAnalyzeExpr,
		Filter:       `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("airtable", "pat"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("14")+"\\."+utils.Hex("64"), 3.3))
	return utils.Validate(r, tps, nil)
}

func AirtableOAuthToken() *config.Rule {
	r := config.Rule{
		Description:  "Detected an Airtable OAuth token, which may allow unauthorized access to Airtable resources granted to an OAuth integration.",
		RuleID:       "airtable-oauth-token",
		Confidence:   "high",
		Regex:        utils.GenerateSemiGenericRegex([]string{"airtable"}, `[A-Z0-9]+\.v1\.[A-Z0-9_-]+\.[a-f0-9]+`, true),
		Keywords:     []string{"airtable"},
		ValidateExpr: airtableValidateExpr,
		AnalyzeExpr:  airtableAnalyzeExpr,
		Filter:       `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
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
