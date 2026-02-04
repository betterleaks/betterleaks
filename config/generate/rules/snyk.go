package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
)

func Snyk() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "snyk-api-token",

		Regex:    utils2.GenerateSemiGenericRegex([]string{"snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token)"}, utils2.Hex8_4_4_4_12(), true),
		Keywords: []string{"snyk"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("snyk", "12345678-ABCD-ABCD-ABCD-1234567890AB")
	tps = append(tps,
		`const SNYK_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
		`const SNYK_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // gitleaks:allow
		`SNYK_TOKEN := "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // gitleaks:allow
		`SNYK_TOKEN ::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,     // gitleaks:allow
		`SNYK_TOKEN :::= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // gitleaks:allow
		`SNYK_TOKEN ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,      // gitleaks:allow
		`SNYK_API_KEY ?= "12345678-ABCD-ABCD-ABCD-1234567890AB"`,    // gitleaks:allow
		`SNYK_API_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`,   // gitleaks:allow
		`SNYK_OAUTH_TOKEN = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, // gitleaks:allow
	)
	return utils2.Validate(r, tps, nil)
}
