package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/regexp"
)

func AgeSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.",
		RuleID:      "age-secret-key",
		Regex:       regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
		Keywords:    []string{"AGE-SECRET-KEY-1"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("age", `AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ`) // gitleaks:allow
	return utils2.Validate(r, tps, nil)
}
