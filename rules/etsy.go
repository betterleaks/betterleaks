package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "etsy-open-api-key",
	Confidence:  "high",
	Description: "Found an Etsy Open API key, potentially compromising Etsy app access and shop integrations.",
	Regex:       rulebuilder.Assignment([]string{"etsy", "x-api-key"}, `(?i)`+rulebuilder.AlphaNumeric("24")+`:`+rulebuilder.AlphaNumeric("10,64")),
	Keywords: []string{
		"etsy",
		"x-api-key",
	},
	ValidateExpr: `let k = split(finding["secret"], ":")[0]; (let r = http.get("https://api.etsy.com/v3/application/openapi-ping", {
      "x-api-key": k,
      "Accept": "application/json"
    }); r.status == 200 ? {
      "result": "valid"
    } : r.status in [401, 403] ? {
      "result": "invalid",
      "reason": "Unauthorized"
    } : validate.unknown(r))`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "x-api-key: 1aa2bb33c44d55eeeeee6fff:a1b2c3d4e5", "1aa2bb33c44d55eeeeee6fff:a1b2c3d4e5"),
		rulebuilder.Match("true positive 2", "ETSY_API_KEY=1aa2bb33c44d55eeeeee6fff:a1b2c3d4e5", "1aa2bb33c44d55eeeeee6fff:a1b2c3d4e5"),
		rulebuilder.NoMatch("false positive 1", "ETSY_API_KEY=your_api_key:your_key_here"),
	},
})
