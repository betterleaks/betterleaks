package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

const devCycleValidationExpr = `let r = http.post("https://bucketing-api.devcycle.com/v1/variables", {
    "Authorization": "Bearer " + finding["secret"],
    "Content-Type": "application/json"
  }, "{\"user_id\":\"betterleaks-validation-user\"}"); r.status == 200 ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

func DevCycleClientSDKKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "devcycle-client-sdk-key",
		Description:  "DevCycle client SDK key.",
		Regex:        regexp.MustCompile(`\b(dvc_client_[A-Za-z0-9]{8,32})`),
		Keywords:     []string{"dvc_client_"},
		ValidateExpr: devCycleValidationExpr,
		Filter:       utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("devcycle", "dvc_client_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("24"), 3.0)),
	}
	fps := []string{
		`dvc_client_short`,
	}
	return utils.Validate(r, tps, fps)
}

func DevCycleMobileSDKKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "devcycle-mobile-sdk-key",
		Description:  "DevCycle mobile SDK key.",
		Regex:        regexp.MustCompile(`\b(dvc_mobile_[A-Za-z0-9]{8,32})`),
		Keywords:     []string{"dvc_mobile_"},
		ValidateExpr: devCycleValidationExpr,
		Filter:       utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("devcycle", "dvc_mobile_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("24"), 3.0)),
	}
	fps := []string{
		`dvc_mobile_short`,
	}
	return utils.Validate(r, tps, fps)
}

func DevCycleServerSDKKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "devcycle-server-sdk-key",
		Description:  "DevCycle server SDK key.",
		Regex:        regexp.MustCompile(`\b(dvc_server_[A-Za-z0-9]{8,32})`),
		Keywords:     []string{"dvc_server_"},
		ValidateExpr: devCycleValidationExpr,
		Filter:       utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("devcycle", "dvc_server_"+secrets.NewSecretWithEntropy(utils.AlphaNumeric("24"), 3.0)),
	}
	fps := []string{
		`dvc_server_short`,
	}
	return utils.Validate(r, tps, fps)
}
