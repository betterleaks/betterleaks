package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func NPM() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "npm-access-token",
		Confidence:  "high",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		Regex:       utils.GenerateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true),
		Keywords: []string{
			"npm_",
		},
		Filter: `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("npmAccessToken", "npm_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("36"), 2))
	return utils.Validate(r, tps, nil)
}

func NPMLegacyToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "npm-legacy-token",
		Confidence:   "medium",
		Description:  "Uncovered a legacy npm access token (UUID format), potentially compromising package management and code repository access.",
		Regex:        regexp.MustCompile(`(?i:npm)(?:.|[\n\r]){0,40}?\b(` + utils.Hex8_4_4_4_12() + `)\b`),
		Keywords:     []string{"npm"},
		ValidateExpr: utils.BearerGetValidationExpr("https://registry.npmjs.org/-/whoami", "true"),
		Filter:       utils.MinEntropyAndTokenEfficiency,
	}

	// validate
	token := secrets.NewSecretWithEntropy(utils.Hex8_4_4_4_12(), 3.0)
	tps := []string{
		`NPM_TOKEN=` + token,
		`npm_token: "` + token + `"`,
		`//registry.npmjs.org/:_authToken=` + token,
	}
	fps := []string{
		`NPM_TOKEN=00000000-0000-0000-0000-000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
