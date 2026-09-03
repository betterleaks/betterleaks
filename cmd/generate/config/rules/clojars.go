package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

func Clojars() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "clojars-api-token",
		Confidence:  "high",
		Description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
		Regex:       regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`),
		Keywords:    []string{"clojars_"},
		Filter:      `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("clojars", "CLOJARS_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("60"), 2))
	return utils.Validate(r, tps, nil)
}
