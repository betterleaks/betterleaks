package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://docs.coveralls.io/api-repos-endpoint
// Personal API tokens authenticate as "Authorization: token <token>".
// GET /api/repos lists the caller's repositories. Invalid tokens return 403 {"error":"Forbidden"}.
const coverallsValidateExpr = `let r = http.get("https://coveralls.io/api/repos", {
  "Authorization": "token " + finding["secret"],
  "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};

r.status == 200 && type(body?.repos) == "array" ? {
  "result": "valid"
} : r.status == 403 && body?.error == "Forbidden" ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`

var _ = rulebuilder.Add(config.Rule{
	ID:           "coveralls-personal-api-token",
	Confidence:   "medium",
	Description:  "Detected a Coveralls personal API token, which may expose repository coverage data.",
	Regex:        rulebuilder.Assignment([]string{"coveralls"}, `(?i)[A-Za-z0-9-]{36,37}`),
	Keywords:     []string{"coveralls"},
	ValidateExpr: coverallsValidateExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "coveralls_SECRETTOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t"),
		rulebuilder.Match("true positive 2", "coveralls-SECRET-KEY=m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f", "m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f"),
		rulebuilder.Match("true positive 3", "coveralls_PRIVATEKEY=1234567890bcdefghijklmnpqrstuvwxyza12", "1234567890bcdefghijklmnpqrstuvwxyza12"),
		rulebuilder.Match("true positive 4", "coveralls_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8"),
	},
})
