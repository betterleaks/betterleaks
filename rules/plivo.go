package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "plivo-auth-id",
	Confidence:  "high",
	Description: "Plivo Auth ID, used as a component of the Plivo Auth Token composite rule.",
	Regex: rulebuilder.Assignment(
		[]string{`plivo(?:[_. -]*(?:auth|account))?[_. -]*(?:id|sid)`},
		`(?i)MA[A-Z0-9]{18}`,
	),
	Keywords:   []string{"plivo"},
	SkipReport: true,
	FilterExpr: `entropy(finding["secret"]) < 2.8 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "PLIVO_AUTH_ID=MA5FBBD6P84OE7UT4QRT", "MA5FBBD6P84OE7UT4QRT"),
		rulebuilder.NoMatchComponent("false positive 1", "ACCOUNT_ID=MABDY4DMVMZESYNGY0NV"),
		rulebuilder.NoMatchComponent("false positive 2", "PLIVO_AUTH_ID=MA000000000000000000"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "plivo-auth-token",
	Confidence:  "high",
	Description: "Plivo Auth Token.",
	Regex: rulebuilder.Assignment(
		[]string{`plivo(?:[_. -]*(?:auth))?[_. -]*(?:secret|token|key)`},
		`[A-Za-z0-9_-]{40}`,
	),
	Keywords: []string{"plivo"},
	Components: []config.Component{
		{RuleID: "plivo-auth-id"},
	},
	ValidateExpr: `let authID = (components["plivo-auth-id"]?.secret ?? "");
let r = http.get("https://api.plivo.com/v1/Account/" + authID + "/", {
  "Authorization": "Basic " + base64.encode(bytes(authID + ":" + finding["secret"])),
  "Accept": "application/json"
}); r.status == 200 ? {
  "result": "valid"
} : r.status == 403 ? {
  "result": "valid",
  "reason": "Authenticated but account access is restricted"
} : r.status == 401 ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "PLIVO_AUTH_TOKEN=WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH\nPLIVO_AUTH_ID=MA5FBBD6P84OE7UT4QRT",
			Expect: []config.ExpectedFinding{
				{Secret: "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH", ComponentSets: []map[string]string{{"plivo-auth-id": "MA5FBBD6P84OE7UT4QRT"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "AUTH_TOKEN=qFj32Da8vf-g_-8qLu9P_k8XPyAHGrvKrzGTQIN4"),
		rulebuilder.NoMatch("false positive 2", "PLIVO_AUTH_TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})
