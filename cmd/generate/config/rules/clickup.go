package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func ClickUpPersonalAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "clickup-personal-api-token",
		Description: "Detected a ClickUp personal API token, which may allow unauthorized access to ClickUp workspaces and user data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"clickup"}, `pk_`+utils.Numeric("8,9")+`_`+utils.AlphaNumeric("32"), true),
		Keywords:    []string{"clickup"},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.clickup.com/api/v2/user", {
    "Accept": "application/json",
    "Authorization": finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid",
    "username": r.json.?user.?username.orValue(""),
    "email": r.json.?user.?email.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: utils.MinEntropy(3.5),
	}

	tps := []string{
		`CLICKUP_API_TOKEN=pk_204249739_138RCYNYCVO0GRJ8INODHFRMXN0QSV75`,
		`clickup_token: "pk_204249739_GSJCPRLQEX43KH4WN8093RZ9DW3CJGM4"`,
	}
	fps := []string{
		`API_TOKEN=pk_204249739_138RCYNYCVO0GRJ8INODHFRMXN0QSV75`,
		`CLICKUP_API_TOKEN=pk_2042497_138RCYNYCVO0GRJ8INODHFRMXN0QSV75`,
	}
	return utils.Validate(r, tps, fps)
}
