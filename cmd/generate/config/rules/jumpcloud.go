package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func JumpCloudAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "jumpcloud-api-key",
		Description: "Detected a JumpCloud API key, which may expose JumpCloud directory data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"jumpcloud"}, utils.AlphaNumeric("40"), true),
		Keywords:    []string{"jumpcloud"},
		ValidateCEL: `cel.bind(r,
  http.get("https://console.jumpcloud.com/api/systemusers?limit=1&skip=0", {
    "x-api-key": finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"results\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`jumpcloud_api_key=1a2b3c4d5e6f7g8h9i0j1a2b3c4d5e6f7g8h9i0j`,
		`JUMPCLOUD_SECRET=k9l8m7n6o5p4q3r2s1t0k9l8m7n6o5p4q3r2s1t0`,
	}
	return utils.Validate(r, tps, nil)
}
