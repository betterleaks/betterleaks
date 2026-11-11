package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://developers.figma.com/docs/rest-api/users-endpoints/
const figmaValidateExpr = `let r = http.get("https://api.figma.com/v1/me", {
  "X-Figma-Token": finding["secret"]
});
r.status == 200 && type(r.json) == "map" && (r.json?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.id ?? ""),
      "username": string(r.json?.handle ?? ""),
      "email": string(r.json?.email ?? "")
    }
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const figmaAnalyzeExpr = identityOnlyAnalyzeExpr

var _ = Add(config.Rule{
	Description:  "Uncovered a Figma Personal Access Token, which may compromise design assets and team collaboration.",
	ID:           "figma-personal-access-token",
	Confidence:   "high",
	Regex:        Token(`(?i)figd_[A-Z0-9_-]{38,42}`),
	Keywords:     []string{"figd_"},
	ValidateExpr: figmaValidateExpr,
	AnalyzeExpr:  figmaAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("figma assignment", `figmaToken = "figd_4W8M67_---XGV0Z1WEA3M1DNG_YPVE8FU6YZ88"`, "figd_4W8M67_---XGV0Z1WEA3M1DNG_YPVE8FU6YZ88"),
		Match("true positive 1", "figma pat = figd_rh1234567890123456789012345678901234abcd", "figd_rh1234567890123456789012345678901234abcd"),
		Match("true positive 2", "figma access token: figd_1234567890123456789012345678901234abcdef", "figd_1234567890123456789012345678901234abcdef"),
	},
})

var _ = Add(config.Rule{
	Description:  "Uncovered a Figma Personal Access Token in a header, which may compromise design assets and team collaboration.",
	ID:           "figma-personal-access-header-token",
	Confidence:   "high",
	Regex:        Assignment([]string{"x-figma-token", "xfigmatoken", "x_figma_token"}, `(?i)[0-9A-F]{4}-[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}`),
	Keywords:     []string{"X-Figma-Token", "xfigmatoken", "x_figma_token"},
	ValidateExpr: figmaValidateExpr,
	AnalyzeExpr:  figmaAnalyzeExpr,
	Tests: []config.RuleTest{
		Match("x-figma-token assignment", `x-figma-tokenToken = "1F7B-169C846F-218A-B552-FA82-FBF86758BF5C"`, "1F7B-169C846F-218A-B552-FA82-FBF86758BF5C"),
		Match("true positive 1", "--header='X-Figma-Token: 1394-0ca7a5be-8e22-40ee-8c40-778d41ab2313'", "1394-0ca7a5be-8e22-40ee-8c40-778d41ab2313"),
	},
})
