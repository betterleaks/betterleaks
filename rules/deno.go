package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:           "deno-account-token",
	Confidence:   "high",
	Description:  "Detected a Deno account token, which may expose Deno Deploy account access.",
	Regex:        rulebuilder.Token(`ddp_[A-Za-z0-9]{36}`),
	Keywords:     []string{"ddp_"},
	ValidateExpr: rulebuilder.BearerGetValidationExpr("https://api.deno.com/v1/user", `(r.body contains "\"id\"")`),
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "DENO_DEPLOY_TOKEN=ddp_A7h3Lm9Qw2Rt6Yu8Ks4Vz1Np5Cx0Bd7EfGhJ", "ddp_A7h3Lm9Qw2Rt6Yu8Ks4Vz1Np5Cx0Bd7EfGhJ"),
		rulebuilder.Match("true positive 2", `deno_token = "ddp_M4nT7pQs8Vx1Zc3Df5Gh7Jk9Lm2Np4Qr6StU"`, "ddp_M4nT7pQs8Vx1Zc3Df5Gh7Jk9Lm2Np4Qr6StU"),
	},
})
