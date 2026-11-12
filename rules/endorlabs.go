package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "endorlabs-api-key",
	Confidence:  "high",
	Description: "Detected an Endor Labs API Key, which may compromise supply chain security scanning and software composition analysis.",
	Regex:       rulebuilder.Assignment([]string{"endor(?:labs)?", "key"}, `(?i)endr\+[A-Za-z0-9-]{16}`),
	Keywords:    []string{"endr+"},
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ENDOR_API_CREDENTIALS_KEY=endr+eoStCxpP3EVXcbLq", "endr+eoStCxpP3EVXcbLq"),
		rulebuilder.Match("true positive 2", "endorlabs_api_key=endr+eoStCxpP3EVXcbLq", "endr+eoStCxpP3EVXcbLq"),
		rulebuilder.Match("true positive 3", `endor_key = "endr+eoStCxpP3EVXcbLq"`, "endr+eoStCxpP3EVXcbLq"),
		rulebuilder.NoMatch("Wrong secret prefix", "endorlabs_api_key=endr-foo1234567890abc"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "endorlabs-api-secret",
	Confidence:  "high",
	Description: "Detected an Endor Labs API Secret, which together with an API key grants full access to Endor Labs supply chain security services.",
	Regex:       rulebuilder.Assignment([]string{"endor(?:labs)?", "secret"}, `(?i)endr\+[A-Za-z0-9-]{16}`),
	Keywords:    []string{"endr+"},
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "ENDOR_API_CREDENTIALS_SECRET=endr+eoStCxpP3EVXcbLq", "endr+eoStCxpP3EVXcbLq"),
		rulebuilder.Match("true positive 2", "endorlabs_api_secret=endr+eoStCxpP3EVXcbLq", "endr+eoStCxpP3EVXcbLq"),
		rulebuilder.Match("true positive 3", `endor_secret = "endr+eoStCxpP3EVXcbLq"`, "endr+eoStCxpP3EVXcbLq"),
		rulebuilder.NoMatch("Wrong secret prefix", "endorlabs_api_secret=endr-bar1234567890abc"),
	},
})
