package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func Clojars() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "clojars-api-token",
		Description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
		Regex:       regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`),
		Entropy:     2,
		Keywords:    []string{"clojars_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("clojars", "CLOJARS_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("60"), 2))
	return utils.Validate(r, tps, nil)
}
