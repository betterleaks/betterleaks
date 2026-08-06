package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func CloudsmithAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudsmith-api-key",
		Description: "Detected a Cloudsmith API key, which may expose package repositories and artifact management operations to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`csa_[a-f0-9]{30}[A-Za-z0-9]{6}`, false),
		Keywords:    []string{"csa_"},
		ValidateExpr: `let r = http.get("https://api.cloudsmith.io/user/self/", {
    "Authorization": "Bearer " + finding["secret"]
  }); r.status == 200 && (r.json?.authenticated ?? false) == true ? {
    "result": "valid",
    "account": (r.json?.slug ?? "")
  } : r.status in [401, 403] || (r.status == 200 && (r.json?.authenticated ?? false) == false) ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	tps := utils.GenerateSampleSecrets("cloudsmith", "csa_93d7f5d17b39f506a607a3c4f61794Q1phUk")
	fps := []string{
		`cloudsmith = "csa_93d7f5d16b39f506a607a3c4f61794Q1phU"`,
		`cloudsmith = "csb_93d7f5d16b39f506a607a3c4f61794Q1phUQ"`,
	}
	return utils.Validate(r, tps, fps)
}
