package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

const polarUserTokenValidateExpr = `let r = http.get("https://api.polar.sh/v1/oauth2/userinfo", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"sub\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but user-info access is restricted"
  } : r.status == 401 && (r.json?.error ?? "") == "invalid_token" ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`

var _ = rulebuilder.Add(config.Rule{
	ID:          "polar-organization-access-token",
	Confidence:  "high",
	Description: "Polar organization access token.",
	Regex:       rulebuilder.Token(`polar_oat_[A-Za-z0-9_-]{20,100}`),
	Keywords:    []string{"polar_oat_"},
	ValidateExpr: `let r = http.get("https://api.polar.sh/v1/organizations/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"items\"") ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but organization access is restricted"
  } : r.status == 401 && (r.json?.error ?? "") == "invalid_token" ? {
    "result": "invalid",
    "reason": "Invalid token"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "POLAR_ACCESS_TOKEN=polar_oat_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH", "polar_oat_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"),
		rulebuilder.NoMatch("false positive 1", "polar_oat_short"),
		rulebuilder.NoMatch("false positive 2", "polar_oat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:           "polar-personal-access-token",
	Confidence:   "high",
	Description:  "Polar personal access token.",
	Regex:        rulebuilder.Token(`polar_pat_[A-Za-z0-9_-]{20,100}`),
	Keywords:     []string{"polar_pat_"},
	ValidateExpr: polarUserTokenValidateExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "POLAR_ACCESS_TOKEN=polar_pat_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH", "polar_pat_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"),
		rulebuilder.NoMatch("false positive 1", "polar_pat_short"),
		rulebuilder.NoMatch("false positive 2", "polar_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:           "polar-oauth-access-token",
	Confidence:   "high",
	Description:  "Polar OAuth access token.",
	Regex:        rulebuilder.Token(`polar_at_[A-Za-z0-9_-]{20,100}`),
	Keywords:     []string{"polar_at_"},
	ValidateExpr: polarUserTokenValidateExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "POLAR_ACCESS_TOKEN=polar_at_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH", "polar_at_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"),
		rulebuilder.NoMatch("false positive 1", "polar_at_short"),
		rulebuilder.NoMatch("false positive 2", "polar_at_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
