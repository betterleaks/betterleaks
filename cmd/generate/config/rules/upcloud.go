package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func UpCloud() *config.Rule {
	r := config.Rule{
		RuleID:      "upcloud-api-token",
		Description: "Identified an UpCloud API token, which may expose cloud infrastructure resources to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`ucat_[0-9A-Za-z]{24,32}`, false),
		Keywords:    []string{"ucat_"},
		Entropy:     3.0,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.upcloud.com/1.3/account", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && r.body.contains('"account"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := []string{
		utils.GenerateSampleSecret("upcloud", "ucat_"+secrets.NewSecretWithEntropy(`[0-9A-Z]{26}`, 3.0)),
	}
	fps := []string{
		// Too short
		`upcloud_token = ucat_01DQE3`,
		// Wrong prefix
		`upcloud_token = uca_01DQE3AJDEBFEKECFM558TGH2F`,
	}
	return utils.Validate(r, tps, fps)
}
