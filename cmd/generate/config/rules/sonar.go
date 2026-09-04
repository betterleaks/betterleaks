package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Sonar() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "sonar-api-token",
		Confidence:  "high",
		Regex:       utils.GenerateSemiGenericRegex([]string{"sonar[_.-]?(login|token)"}, "(?:squ_|sqp_|sqa_)?"+utils.AlphaNumericExtended("40"), true),
		Keywords:    []string{"sonar"},
		SecretGroup: 2,
	}

	// validate
	tps := utils.GenerateSampleSecrets("sonar", "12345678ABCDEFH1234567890ABCDEFH12345678")
	tps = append(tps,
		`const SONAR_LOGIN = "12345678ABCDEFH1234567890ABCDEFH12345678"`,     // betterleaks:allow
		`SONAR_LOGIN := "12345678ABCDEFH1234567890ABCDEFH12345678"`,          // betterleaks:allow
		`SONAR.LOGIN ::= "12345678ABCDEFH1234567890ABCDEFH12345678"`,         // betterleaks:allow
		`SONAR.LOGIN :::= "12345678ABCDEFH1234567890ABCDEFH12345678"`,        // betterleaks:allow
		`SONAR.LOGIN ?= "12345678ABCDEFH1234567890ABCDEFH12345678"`,          // betterleaks:allow
		`const SONAR_TOKEN = "squ_12345678ABCDEFH1234567890ABCDEFH12345678"`, // betterleaks:allow
		`SONAR_LOGIN := "sqp_12345678ABCDEFH1234567890ABCDEFH12345678"`,      // betterleaks:allow
		`SONAR.TOKEN = "sqa_12345678ABCDEFH1234567890ABCDEFH12345678"`,       // betterleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
