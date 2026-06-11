package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func LobPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
		RuleID:      "lob-pub-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`, true),

		Keywords: []string{
			"test_pub_",
			"live_pub_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("lob", "test_pub_"+secrets.NewSecret(utils.Hex("31")))
	return utils.Validate(r, tps, nil)
}

func LobAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
		RuleID:      "lob-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"lob"}, `(live|test)_[a-f0-9]{35}`, true),
		Keywords: []string{
			"test_",
			"live_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("lob", "test_"+secrets.NewSecret(utils.Hex("35")))
	return utils.Validate(r, tps, nil)
}
