package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func HarnessApiKey() *config.Rule {
	// Define rule for Harness Personal Access Token (PAT) and Service Account Token (SAT)
	r := config.Rule{
		Description: "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
		RuleID:      "harness-api-key",
		Regex:       regexp.MustCompile(`(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}`),
		Keywords:    []string{"pat.", "sat."},
	}

	// Generate a sample secret for validation
	tps := utils2.GenerateSampleSecrets("harness", "pat."+secrets.NewSecret(utils2.AlphaNumeric("22"))+"."+secrets.NewSecret(utils2.AlphaNumeric("24"))+"."+secrets.NewSecret(utils2.AlphaNumeric("20")))
	tps = append(tps, utils2.GenerateSampleSecrets("harness", "sat."+secrets.NewSecret(utils2.AlphaNumeric("22"))+"."+secrets.NewSecret(utils2.AlphaNumeric("24"))+"."+secrets.NewSecret(utils2.AlphaNumeric("20")))...)

	// validate the rule
	return utils2.Validate(r, tps, nil)
}
