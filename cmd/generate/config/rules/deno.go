package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func DenoAccountToken() *config.Rule {
	r := config.Rule{
		RuleID:      "deno-account-token",
		Description: "Detected a Deno account token, which may expose Deno Deploy account access.",
		Regex:       utils.GenerateUniqueTokenRegex(`ddp_[A-Za-z0-9]{36}`, false),
		Keywords:    []string{"ddp_"},
		ValidateCEL: utils.BearerGetValidationCEL("https://api.deno.com/v1/user", "r.body.contains(\"\\\"id\\\"\")"),
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`DENO_DEPLOY_TOKEN=ddp_A7h3Lm9Qw2Rt6Yu8Ks4Vz1Np5Cx0Bd7EfGhJ`,
		`deno_token = "ddp_M4nT7pQs8Vx1Zc3Df5Gh7Jk9Lm2Np4Qr6StU"`,
	}
	return utils.Validate(r, tps, nil)
}
