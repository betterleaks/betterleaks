package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func GumroadAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gumroad-access-token",
		Description: "Detected a Gumroad access token, which may expose Gumroad account and product data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"gumroad"}, `(?:[a-f0-9]{64}|[A-Za-z0-9-]{43})`, true),
		Keywords:    []string{"gumroad"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.gumroad.com/v2/user?access_token=" + finding["secret"], {
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"success\":true") && r.body.contains("\"user\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`gumroad_access_token=abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505`,
		`gumroadPRIVATE=abf11e4ab2850ffd50ef690257f7a1c998a443059513d1a4826f2b3159620505`,
	}
	return utils.Validate(r, tps, nil)
}
