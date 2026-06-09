package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func ClickUpPersonalAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "clickup-personal-api-token",
		Description: "Detected a ClickUp personal API token, which may allow unauthorized access to ClickUp workspaces and user data.",
		Regex:       regexp.MustCompile(`(?i)\bclickup(?:.|[\n\r]){0,32}?\b(pk_\d{8,9}_[0-9A-Z]{32})\b`),
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
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
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
