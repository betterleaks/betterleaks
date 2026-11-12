package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
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

const boxAnalyzeExpr = rulebuilder.IdentityOnlyAnalyzeExpr

var _ = rulebuilder.Add(config.Rule{
	ID:           "box-api-access-token",
	Confidence:   "medium",
	Description:  "Detected a Box API access token, which may expose Box files and account data.",
	Regex:        rulebuilder.Assignment([]string{"box"}, `(?i)`+rulebuilder.AlphaNumeric("32")),
	Keywords:     []string{"box_", "box-", "boxt", "boxk", "boxa"},
	ValidateExpr: boxValidateExpr,
	AnalyzeExpr:  boxAnalyzeExpr,
	// Include any identifier prefix before the regex's "box" match, but
	// exclude values and neighboring assignments from the client check.
	FilterExpr: `let prefix = findMatch(finding["fragment_raw"][finding["match_line_start_idx"]:finding["match_start_idx"]], "[\\w.-]*$");
let identifier = prefix + findMatch(finding["match"], "^[\\w .-]+");
lower(identifier) contains "client" || entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `BOX_DEVELOPER_TOKEN="DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"`, "DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"),
		rulebuilder.Match("true positive 2", "box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'", "A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"),
		rulebuilder.Match("true positive 3", "box_access_token = 'clientA4bC5dE6fG7hI8jK9lM0nO1pQ2'", "clientA4bC5dE6fG7hI8jK9lM0nO1pQ2"),
		rulebuilder.Match("true positive 4", `client_id="example"; box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'`, "A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"),
		rulebuilder.Match("true positive 5", "box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4' # client credentials are separate", "A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"),
		rulebuilder.Match("true positive 6", "box_access_token =\n\"A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4\"", "A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"),
		rulebuilder.NoMatch("false positive 1", `BOX_DOC_URL="https://developer.box.com"`),
		rulebuilder.NoMatch("false positive 2", "sandbox_mode = true"),
		rulebuilder.NoMatch("false positive 3", "box_client_id= A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4"),
		rulebuilder.NoMatch("false positive 4", "box_client_secret=DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"),
		rulebuilder.NoMatch("false positive 5", `BOX_CLIENT_SECRET="DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"`),
		rulebuilder.NoMatch("false positive 6", `{"boxClientSecret": "DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG"}`),
		rulebuilder.NoMatch("false positive 7", "box-client-token: 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'"),
		rulebuilder.NoMatch("false positive 8", "client_box_access_token = 'A4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4'"),
		rulebuilder.NoMatch("false positive 9", "box_client_secret =\n\"DkXZmsjUKizvL2z0WiaLvMBeQ756XCGG\""),
	},
})
