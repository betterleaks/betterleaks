package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "bitrise-access-token",
	Confidence:  "high",
	Description: "Detected a Bitrise personal or workspace access token, which may expose CI/CD applications and builds.",
	Regex: rulebuilder.Assignment(
		[]string{`bitrise(?:[ _-]*(?:personal|workspace))?(?:[ _-]*(?:access|api))?[ _-]*token`},
		`[A-Za-z0-9_-]{60,120}`,
	),
	Keywords: []string{"bitrise"},
	ValidateExpr: `let r = http.get("https://api.bitrise.io/v0.1/apps", {
    "Authorization": finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "BITRISE_TOKEN=R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7", "R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7"),
		rulebuilder.Match("true positive 2", "bitrise workspace api token: Q9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV", "Q9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV"),
		rulebuilder.NoMatch("false positive 1", "TOKEN=R7mQ2vN9xK4pT8cW1zL6gH3sD5fJ0aB7nM2qV9xK4pT8cW1zL6gH3sD5fJ0aB7"),
		rulebuilder.NoMatch("false positive 2", "BITRISE_TOKEN=too_short"),
	},
})
