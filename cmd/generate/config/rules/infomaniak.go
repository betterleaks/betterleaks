package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Infomaniak() *config.Rule {
	r := config.Rule{
		RuleID:      "infomaniak-api-token",
		Description: "Detected an Infomaniak API token, which may expose hosting, mail, and cloud services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"infomaniak"}, `[A-Za-z0-9_\-]{60,100}`, true),
		Keywords:    []string{"infomaniak"},
		Entropy:     4.0,
		ValidateCEL: `cel.bind(r,
  http.get("https://api.infomaniak.com/1/profile", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && r.body.contains('"result"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	tps := utils.GenerateSampleSecrets("infomaniak", secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-]{72}`, 4.0))
	fps := []string{
		// Too short
		`infomaniak_token = "AYF5lSh3c7Xy"`,
	}
	return utils.Validate(r, tps, fps)
}
