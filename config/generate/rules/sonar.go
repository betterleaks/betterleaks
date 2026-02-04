package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
)

func Sonar() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "sonar-api-token",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"sonar[_.-]?(login|token)"}, "(?:squ_|sqp_|sqa_)?"+utils2.AlphaNumericExtended("40"), true),
		Keywords:    []string{"sonar"},
		SecretGroup: 2,
	}

	// validate
	tps := utils2.GenerateSampleSecrets("sonar", "12345678ABCDEFH1234567890ABCDEFH12345678")
	tps = append(tps,
		`const SONAR_LOGIN = "12345678ABCDEFH1234567890ABCDEFH12345678"`,     // gitleaks:allow
		`SONAR_LOGIN := "12345678ABCDEFH1234567890ABCDEFH12345678"`,          // gitleaks:allow
		`SONAR.LOGIN ::= "12345678ABCDEFH1234567890ABCDEFH12345678"`,         // gitleaks:allow
		`SONAR.LOGIN :::= "12345678ABCDEFH1234567890ABCDEFH12345678"`,        // gitleaks:allow
		`SONAR.LOGIN ?= "12345678ABCDEFH1234567890ABCDEFH12345678"`,          // gitleaks:allow
		`const SONAR_TOKEN = "squ_12345678ABCDEFH1234567890ABCDEFH12345678"`, // gitleaks:allow
		`SONAR_LOGIN := "sqp_12345678ABCDEFH1234567890ABCDEFH12345678"`,      // gitleaks:allow
		`SONAR.TOKEN = "sqa_12345678ABCDEFH1234567890ABCDEFH12345678"`,       // gitleaks:allow
	)
	return utils2.Validate(r, tps, nil)
}
