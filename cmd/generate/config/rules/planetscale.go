package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func PlanetScalePassword() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-password",
		Description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
		Regex:       utils.GenerateUniqueTokenRegex(`pscale_pw_(?i)[\w=\.-]{32,64}`, true),
		Entropy:     3,
		Keywords: []string{
			"pscale_pw_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("planetScale", "pscale_pw_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("32"), 3))
	tps = append(tps, utils.GenerateSampleSecrets("planetScale", "pscale_pw_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("43"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("planetScale", "pscale_pw_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("64"), 3))...)
	return utils.Validate(r, tps, nil)
}

// PlanetScaleID detects PlanetScale service token IDs.
// This is a dependency rule for PlanetScaleAPIToken and is not reported on its own.
func PlanetScaleID() *config.Rule {
	r := config.Rule{
		RuleID:      "planetscale-id",
		Description: "Found a PlanetScale service token ID.",
		Regex: regexp.MustCompile(
			`(?i)(?:pscale|planetscale)(?:.|[\n\r]){0,16}?(?:USER|ID|NAME)(?:.|[\n\r]){0,16}?([a-z0-9]{12})`,
		),
		Entropy:    3,
		Keywords:   []string{"pscale", "planetscale"},
		SkipReport: true,
	}

	tps := []string{
		"pscale_user = 0dm7fw8prpel",
		"planetscale_id: 0dm7fw8prpel",
		"PSCALE_USER_NAME = " + secrets.NewSecretWithEntropy(`[a-z0-9]{12}`, 3),
	}
	return utils.Validate(r, tps, nil)
}

func PlanetScaleAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-api-token",
		Description: "Identified a PlanetScale API token, potentially compromising database management and operations.",
		Regex:       utils.GenerateUniqueTokenRegex(`pscale_tkn_(?i)[\w=\.-]{32,64}`, false),
		Entropy:     3,
		Keywords: []string{
			"pscale_tkn_",
		},
		RequiredRules: []*config.Required{
			{RuleID: "planetscale-id"},
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.planetscale.com/v1/organizations", {
    "Accept": "application/json",
    "Authorization": captures["planetscale-id"] + ":" + secret
  }),
  r.status == 200 && r.json.?type.orValue("") == "list" ? {
    "result": "valid",
    "organization": r.json.?data[0].?name.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("planetScale", "pscale_tkn_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("32"), 3))
	tps = append(tps, utils.GenerateSampleSecrets("planetScale", "pscale_tkn_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("43"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("planetScale", "pscale_tkn_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("64"), 3))...)
	return utils.Validate(r, tps, nil)
}

func PlanetScaleOAuthToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-oauth-token",
		Description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
		Regex:       utils.GenerateUniqueTokenRegex(`pscale_oauth_[\w=\.-]{32,64}`, false),
		Entropy:     3,
		Keywords: []string{
			"pscale_oauth_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("planetScale", "pscale_oauth_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("32"), 3))
	tps = append(tps, utils.GenerateSampleSecrets("planetScale", "pscale_oauth_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("43"), 3))...)
	tps = append(tps, utils.GenerateSampleSecrets("planetScale", "pscale_oauth_"+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("64"), 3))...)
	return utils.Validate(r, tps, nil)
}
