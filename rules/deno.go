package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:           "deno-account-token",
	Confidence:   "high",
	Description:  "Detected a Deno account token, which may expose Deno Deploy account access.",
	Regex:        Token(`ddp_[A-Za-z0-9]{36}`),
	Keywords:     []string{"ddp_"},
	ValidateExpr: BearerGetValidationExpr("https://api.deno.com/v1/user", `(r.body contains "\"id\"")`),
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "DENO_DEPLOY_TOKEN=ddp_A7h3Lm9Qw2Rt6Yu8Ks4Vz1Np5Cx0Bd7EfGhJ", "ddp_A7h3Lm9Qw2Rt6Yu8Ks4Vz1Np5Cx0Bd7EfGhJ"),
		Match("true positive 2", `deno_token = "ddp_M4nT7pQs8Vx1Zc3Df5Gh7Jk9Lm2Np4Qr6StU"`, "ddp_M4nT7pQs8Vx1Zc3Df5Gh7Jk9Lm2Np4Qr6StU"),
	},
})
