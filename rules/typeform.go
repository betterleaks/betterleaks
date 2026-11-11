package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "typeform-api-token",
	Confidence:  "high",
	Description: "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.",
	Regex: Assignment([]string{"typeform"},
		`(?i)tfp_[a-z0-9\-_\.=]{59}`),
	Keywords: []string{
		"tfp_",
	},
	Tests: []config.RuleTest{
		Match("typeformAPIToken assignment", `typeformAPITokenToken = "tfp_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa"`, "tfp_ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa"),
	},
})
