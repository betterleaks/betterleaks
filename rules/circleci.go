package rules

import "github.com/betterleaks/betterleaks/v2/config"

// https://circleci.com/docs/api/v2/index.html#operation/getCurrentUser
const circleciValidateExpr = `let r = http.get("https://circleci.com/api/v2/me", {
  "Circle-Token": finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && type(r.json) == "map" && (r.json?.id ?? "") != "" ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(r.json?.id ?? ""),
      "username": string(r.json?.login ?? ""),
      "name": string(r.json?.name ?? "")
    },
    "metadata": {}
  }
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

const circleciAnalyzeExpr = identityOnlyAnalyzeExpr

var _ = Add(config.Rule{
	ID:           "circleci-personal-token",
	Confidence:   "high",
	Description:  "CircleCI personal access token.",
	Regex:        `\b(CCIPAT_[a-zA-Z0-9]{22}_[a-z0-9]{40})`,
	Keywords:     []string{"CCIPAT_"},
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	ValidateExpr: circleciValidateExpr,
	AnalyzeExpr:  circleciAnalyzeExpr,
	Tests: []config.RuleTest{
		Match("bare secret", "CCIPAT_FERZRjTN451xnDCy1y9gWn_79fb6ca4d0e5f833612eee17de397a9dca0a9e9f", "CCIPAT_FERZRjTN451xnDCy1y9gWn_79fb6ca4d0e5f833612eee17de397a9dca0a9e9f"),
		NoMatch("false positive 1", "CCIPAT_short"),
	},
})

var _ = Add(config.Rule{
	ID:          "circleci-project-token",
	Confidence:  "high",
	Description: "CircleCI project token.",
	Regex:       Assignment([]string{"circleci"}, `(?i)[a-f0-9]{40}`),
	Keywords:    []string{"circleci"},
	ValidateExpr: `let r = http.get("https://circleci.com/api/v1.1/projects", {
    "Circle-Token": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", "circleci_project_secret = 'ca61263bf9a4dceecd00edaaacb4eaee74e8682f'", "ca61263bf9a4dceecd00edaaacb4eaee74e8682f"),
		NoMatch("false positive 1", "other_project = 'ca61263bf9a4dceecd00edaaacb4eaee74e8682f'"),
	},
})
