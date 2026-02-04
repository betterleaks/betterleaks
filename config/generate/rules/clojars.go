package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
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
	tps := utils2.GenerateSampleSecrets("clojars", "CLOJARS_"+secrets.NewSecret(utils2.AlphaNumeric("60")))
	return utils2.Validate(r, tps, nil)
}
