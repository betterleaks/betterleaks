package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func LobPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
		RuleID:      "lob-pub-api-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`, true),

		Keywords: []string{
			"test_pub",
			"live_pub",
			"_pub",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("lob", "test_pub_"+secrets.NewSecret(utils2.Hex("31")))
	return utils2.Validate(r, tps, nil)
}

func LobAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
		RuleID:      "lob-api-key",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"lob"}, `(live|test)_[a-f0-9]{35}`, true),
		Keywords: []string{
			"test_",
			"live_",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("lob", "test_"+secrets.NewSecret(utils2.Hex("35")))
	return utils2.Validate(r, tps, nil)
}
