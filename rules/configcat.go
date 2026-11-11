package rules

import "github.com/betterleaks/betterleaks/v2/config"

const configCatValidationExpr = `let r = http.get("https://cdn-global.configcat.com/configuration-files/" + finding["secret"] + "/config_v6.json", {
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403, 404] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

var _ = Add(config.Rule{
	ID:           "configcat-sdk-key",
	Confidence:   "high",
	Description:  "Detected a ConfigCat SDK key, which may allow access to feature flag configuration data.",
	Regex:        Assignment([]string{"configcat"}, `(?i)[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22}`),
	Keywords:     []string{"configcat"},
	ValidateExpr: configCatValidationExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "CONFIGCAT_SDK_KEY=Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h", "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h"),
		Match("true positive 2", `configcat_key: "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h"`, "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h"),
		NoMatch("false positive 1", "CONFIGCAT_SDK_KEY=short"),
		NoMatch("false positive 2", "SDK_KEY=Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h"),
	},
})

var _ = Add(config.Rule{
	ID:           "configcat-sdk-key-extended",
	Confidence:   "high",
	Description:  "Detected an extended ConfigCat SDK key, which may allow access to feature flag configuration data.",
	Regex:        Token(`configcat-sdk-1/[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22}`),
	Keywords:     []string{"configcat-sdk-1"},
	ValidateExpr: configCatValidationExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "CONFIGCAT_SDK_KEY=configcat-sdk-1/Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h", "configcat-sdk-1/Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h"),
		NoMatch("false positive 1", "CONFIGCAT_SDK_KEY=configcat-sdk-1/short/aA1bB2cC3dD4eE5fF6gG7h"),
	},
})
