package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://developer.box.com/reference/get-users-me/
const boxValidateExpr = `let r = http.get("https://api.box.com/2.0/users/me", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && (r.json?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.id ?? ""),
      "name": string(r.json?.name ?? ""),
      "email": string(r.json?.login ?? "")
    },
    "metadata": {}
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const boxAnalyzeExpr = identityOnlyAnalyzeExpr

func BoxAPIAccessToken() *config.Rule {
	r := config.Rule{
		ID:           "box-api-access-token",
		Confidence:   "medium",
		Description:  "Detected a Box API access token, which may expose Box files and account data.",
		Regex:        utils.GenerateSemiGenericRegex([]string{"box"}, utils.AlphaNumeric("32"), true),
		Keywords:     []string{"box_", "box-", "boxt", "boxk", "boxa"},
		ValidateExpr: boxValidateExpr,
		AnalyzeExpr:  boxAnalyzeExpr,
		// Include any identifier prefix before the regex's "box" match, but
		// exclude values and neighboring assignments from the client check.
		FilterExpr: `let prefix = findMatch(finding["fragment_raw"][finding["match_line_start_idx"]:finding["match_start_idx"]], "[\\w.-]*$");
let identifier = prefix + findMatch(finding["match"], "^[\\w .-]+");
lower(identifier) contains "client" || entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := []string{
		`BOX_DEVELOPER_TOKEN="DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"`,
		`box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'`,
		`box_access_token = 'clientA4bC5dE6fG7hI8jK9lM0nO1pQ2'`,
		`client_id="example"; box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'`,
		`box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4' # client credentials are separate`,
		"box_access_token =\n\"A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4\"",
	}
	fps := []string{
		`BOX_DOC_URL="https://developer.box.com"`,
		`sandbox_mode = true`,
		`box_client_id= A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4`,
		`box_client_secret=DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG`,
		`BOX_CLIENT_SECRET="DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"`,
		`{"boxClientSecret": "DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"}`,
		`box-client-token: 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'`,
		`client_box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'`,
		"box_client_secret =\n\"DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG\"",
	}
	return utils.Validate(r, tps, fps)
}
