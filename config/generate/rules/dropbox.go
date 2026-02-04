package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func DropBoxAPISecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Dropbox API secret, which could lead to unauthorized file access and data breaches in Dropbox storage.",
		RuleID:      "dropbox-api-token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"dropbox"}, utils2.AlphaNumeric("15"), true),

		Keywords: []string{"dropbox"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("dropbox", secrets.NewSecret(utils2.AlphaNumeric("15")))
	return utils2.Validate(r, tps, nil)
}

func DropBoxShortLivedAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dropbox-short-lived-api-token",
		Description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"dropbox"}, `sl\.[a-z0-9\-=_]{135}`, true),
		Keywords:    []string{"dropbox"},
	}

	// validate TODO
	return &r
}

func DropBoxLongLivedAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "dropbox-long-lived-api-token",
		Description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"dropbox"}, `[a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43}`, true),
		Keywords:    []string{"dropbox"},
	}

	// validate TODO
	return &r
}
