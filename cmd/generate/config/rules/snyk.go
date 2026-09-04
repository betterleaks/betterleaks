package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Snyk() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "snyk-api-token",
		Confidence:  "high",

		Regex:    utils.GenerateSemiGenericRegex([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, utils.Hex8_4_4_4_12(), true),
		Keywords: []string{"snyk"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("snyk", "12345678-ABCD-ABCD-ABCD-1234567890AB")
	tps = append(tps,
		`const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // betterleaks:allow
		`const SNYK_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // betterleaks:allow
		`SNYK_TOKEN := "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // betterleaks:allow
		`SNYK_TOKEN ::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,     // betterleaks:allow
		`SNYK_TOKEN :::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // betterleaks:allow
		`SNYK_TOKEN ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // betterleaks:allow
		`SNYK_API_KEY ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // betterleaks:allow
		`SNYK_API_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // betterleaks:allow
		`SNYK_OAUTH_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // betterleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
