package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:           "render-api-key",
	Confidence:   "high",
	Description:  "Detected a Render API key, which may expose hosted services and account resources to unauthorized access.",
	Regex:        Token(`rnd_[A-Za-z0-9]{28}`),
	Keywords:     []string{"rnd_"},
	ValidateExpr: BearerGetValidationExpr("https://api.render.com/v1/services?limit=1", "true"),
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("render assignment", `renderToken = "rnd_RFbD56TI2smTyVsGd5Xav0yu99ZA"`, "rnd_RFbD56TI2smTyVsGd5Xav0yu99ZA"),
		NoMatch("false positive 1", "rnd_jYBekhjOgICntzWUNO2ye4yCNKb"),
		NoMatch("false positive 2", "rnd_jYBekhjOgICntzWUNO2ye4y_NKbk"),
	},
})
