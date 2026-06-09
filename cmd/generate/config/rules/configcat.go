package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

const configCatValidationCEL = `cel.bind(r,
  http.get("https://cdn-global.configcat.com/configuration-files/" + finding["secret"] + "/config_v6.json", {
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403, 404] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`

func ConfigCatSDKKey() *config.Rule {
	r := config.Rule{
		RuleID:      "configcat-sdk-key",
		Description: "Detected a ConfigCat SDK key, which may allow access to feature flag configuration data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"configcat"}, `[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22}`, true),
		Keywords:    []string{"configcat"},
		ValidateCEL: configCatValidationCEL,
		Filter:      `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`CONFIGCAT_SDK_KEY=Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h`,
		`configcat_key: "Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h"`,
	}
	fps := []string{
		`CONFIGCAT_SDK_KEY=short`,
		`SDK_KEY=Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h`,
	}
	return utils.Validate(r, tps, fps)
}

func ConfigCatSDKKeyExtended() *config.Rule {
	r := config.Rule{
		RuleID:      "configcat-sdk-key-extended",
		Description: "Detected an extended ConfigCat SDK key, which may allow access to feature flag configuration data.",
		Regex:       utils.GenerateUniqueTokenRegex(`configcat-sdk-1/[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{22}`, false),
		Keywords:    []string{"configcat-sdk-1"},
		ValidateCEL: configCatValidationCEL,
		Filter:      `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`CONFIGCAT_SDK_KEY=configcat-sdk-1/Aa1Bb2Cc3Dd4Ee5Ff6Gg7H/aA1bB2cC3dD4eE5fF6gG7h`,
	}
	fps := []string{
		`CONFIGCAT_SDK_KEY=configcat-sdk-1/short/aA1bB2cC3dD4eE5fF6gG7h`,
	}
	return utils.Validate(r, tps, fps)
}
