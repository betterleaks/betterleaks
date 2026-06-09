package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func BitlyAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "bitly-access-token",
		Description: "Detected a Bitly access token, which may allow unauthorized access to Bitly account and link management APIs.",
		Regex:       regexp.MustCompile(`(?i)\bbitly(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN)(?:.|[\n\r]){0,32}?([a-f0-9]{40})\b`),
		Keywords:    []string{"bitly"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api-ssl.bitly.com/v4/user", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 && r.body.contains("\"login\":") ? {
    "result": "valid",
    "login": r.json.?login.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`bitly_token = 20e9817b9c5ddde1b0cec7622bfc557dbc823791`,
	}
	fps := []string{
		`token = 20e9817b9c5ddde1b0cec7622bfc557dbc823791`,
		`bitly_token = 20e9817b9c5ddde1b0cec7622bfc557dbc82379`,
	}
	return utils.Validate(r, tps, fps)
}
