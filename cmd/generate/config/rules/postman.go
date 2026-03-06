package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PostManAPI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "postman-api-token",
		Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
		Regex:       utils.GenerateUniqueTokenRegex(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`, false),
		Entropy:     3,
		Keywords: []string{
			"PMAK-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("postmanAPItoken", "PMAK-"+secrets.NewSecretWithEntropy(utils.Hex("24"), 3)+"-"+secrets.NewSecretWithEntropy(utils.Hex("34"), 3))
	return utils.Validate(r, tps, nil)
}
