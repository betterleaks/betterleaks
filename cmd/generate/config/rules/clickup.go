package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://developer.clickup.com/reference/getauthorizeduser
const clickupValidateExpr = `let r = http.get("https://api.clickup.com/api/v2/user", {
  "Authorization": finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && type(r.json?.user) == "map" && (r.json?.user?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.user?.id ?? ""),
      "username": string(r.json?.user?.username ?? ""),
      "email": string(r.json?.user?.email ?? "")
    },
    "metadata": {}
  },
  "metadata": {
    "username": string(r.json?.user?.username ?? ""),
    "email": string(r.json?.user?.email ?? "")
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const clickupAnalyzeExpr = identityOnlyAnalyzeExpr

func ClickUpPersonalAPIToken() *config.Rule {
	r := config.Rule{
		ID:           "clickup-personal-api-token",
		Confidence:   "high",
		Description:  "Detected a ClickUp personal API token, which may allow unauthorized access to ClickUp workspaces and user data.",
		Regex:        utils.GenerateSemiGenericRegex([]string{"clickup"}, `pk_`+utils.Numeric("8,9")+`_`+utils.AlphaNumeric("32"), true),
		Keywords:     []string{"clickup"},
		ValidateExpr: clickupValidateExpr,
		AnalyzeExpr:  clickupAnalyzeExpr,
		Filter:       utils.MinEntropy(3.5),
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
