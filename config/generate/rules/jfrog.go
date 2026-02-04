package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func JFrogAPIKey() *config.Rule {
	keywords := []string{"jfrog", "artifactory", "bintray", "xray"}

	// Define Rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.",

		// Unique ID for the rule
		RuleID: "jfrog-api-key",

		// Regex capture group for the actual secret

		// Regex used for detecting secrets. See regex section below for more details
		Regex: utils2.GenerateSemiGenericRegex(keywords, utils2.AlphaNumeric("73"), true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: keywords,
	}
	// validate
	tps := []string{
		fmt.Sprintf("--set imagePullSecretJfrog.password=%s", secrets.NewSecret(utils2.AlphaNumeric("73"))),
	}
	return utils2.Validate(r, tps, nil)
}

func JFrogIdentityToken() *config.Rule {
	keywords := []string{"jfrog", "artifactory", "bintray", "xray"}

	// Define Rule
	r := config.Rule{
		// Human readable description of the rule
		Description: "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.",

		// Unique ID for the rule
		RuleID: "jfrog-identity-token",

		// Regex capture group for the actual secret

		// Regex used for detecting secrets. See regex section below for more details
		Regex: utils2.GenerateSemiGenericRegex(keywords, utils2.AlphaNumeric("64"), true),

		// Keywords used for string matching on fragments (think of this as a prefilter)
		Keywords: keywords,
	}

	// validate
	tps := utils2.GenerateSampleSecrets("jfrog", secrets.NewSecret(utils2.AlphaNumeric("64")))
	tps = append(tps, utils2.GenerateSampleSecrets("artifactory", secrets.NewSecret(utils2.AlphaNumeric("64")))...)
	tps = append(tps, utils2.GenerateSampleSecrets("bintray", secrets.NewSecret(utils2.AlphaNumeric("64")))...)
	tps = append(tps, utils2.GenerateSampleSecrets("xray", secrets.NewSecret(utils2.AlphaNumeric("64")))...)
	tps = append(tps, fmt.Sprintf("\"artifactory\", \"%s\"", secrets.NewSecret(utils2.AlphaNumeric("64"))))
	return utils2.Validate(r, tps, nil)
}
