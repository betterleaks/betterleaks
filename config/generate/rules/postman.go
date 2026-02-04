package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func PostManAPI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "postman-api-token",
		Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
		Regex:       utils2.GenerateUniqueTokenRegex(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`, false),
		Entropy:     3,
		Keywords: []string{
			"PMAK-",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("postmanAPItoken", "PMAK-"+secrets.NewSecret(utils2.Hex("24"))+"-"+secrets.NewSecret(utils2.Hex("34")))
	return utils2.Validate(r, tps, nil)
}
