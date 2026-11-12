package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:           "render-api-key",
	Confidence:   "high",
	Description:  "Detected a Render API key, which may expose hosted services and account resources to unauthorized access.",
	Regex:        rulebuilder.Token(`rnd_[A-Za-z0-9]{28}`),
	Keywords:     []string{"rnd_"},
	ValidateExpr: rulebuilder.BearerGetValidationExpr("https://api.render.com/v1/services?limit=1", "true"),
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `renderToken = "rnd_RFbD56TI2smTyVsGd5Xav0yu99ZA"`, "rnd_RFbD56TI2smTyVsGd5Xav0yu99ZA"),
		rulebuilder.NoMatch("false positive 1", "rnd_jYBekhjOgICntzWUNO2ye4yCNKb"),
		rulebuilder.NoMatch("false positive 2", "rnd_jYBekhjOgICntzWUNO2ye4y_NKbk"),
	},
})
