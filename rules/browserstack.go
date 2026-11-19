package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "browserstack-username.1",
	Confidence:  "medium",
	Description: "BrowserStack username, used as a component of the BrowserStack access-key composite rule.",
	Regex: rulebuilder.Assignment(
		[]string{`browserstack[_.-]?(?:username|user)`},
		`[A-Za-z0-9][A-Za-z0-9._-]{2,39}`,
	),
	Keywords:   []string{"browserstack"},
	SkipReport: true,
	FilterExpr: rulebuilder.MinEntropy(2.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "BROWSERSTACK_USERNAME=RFbD56TI2smT", "RFbD56TI2smT"),
		rulebuilder.MatchComponent("true positive 2", `browserstack.user: "RFbD56TI2smT"`, "RFbD56TI2smT"),
		rulebuilder.NoMatchComponent("false positive 1", "USERNAME=RFbD56TI2smT"),
		rulebuilder.NoMatchComponent("false positive 2", "BROWSERSTACK_USERNAME=ab"),
		rulebuilder.NoMatchComponent("false positive 3", "BROWSERSTACK_USERNAME=aaaaaaaaaaaa"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "browserstack-access-key.1",
	Confidence:  "high",
	Description: "BrowserStack access key, which may allow access to automated browser and device testing when paired with its username.",
	Regex: rulebuilder.Assignment(
		[]string{`browserstack[_.-]?(?:access[_.-]?)?(?:key|secret|token)`},
		`[A-Za-z0-9]{20}`,
	),
	Keywords: []string{"browserstack"},
	Components: []config.Component{
		{RuleID: "browserstack-username.1", Within: "5L"},
	},
	ValidateExpr: `let r = http.get("https://api.browserstack.com/automate/plan.json", {
    "Authorization": "Basic " + base64.encode(bytes((components["browserstack-username.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json",
    "User-Agent": "betterleaks-secret-validation/1"
  }); r.status == 200 && (r.body contains "\"automate_plan\"") ? {
    "result": "valid"
  } : r.status == 403 && ((r.body contains "blocked") || (r.body contains "Blocked")) ?
    validate.unknown(r) : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Authentication failed"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "BROWSERSTACK_ACCESS_KEY=RFbD56TI2smTyVsGd5Xa\nBROWSERSTACK_USERNAME=RFbD56TI2smT",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smTyVsGd5Xa", ComponentSets: []map[string]string{{"browserstack-username.1": "RFbD56TI2smT"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "browserstack.access_key: \"RFbD56TI2smTyVsGd5Xa\"\nBROWSERSTACK_USERNAME=RFbD56TI2smT",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smTyVsGd5Xa", ComponentSets: []map[string]string{{"browserstack-username.1": "RFbD56TI2smT"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "ACCESS_KEY=RFbD56TI2smTyVsGd5Xa"),
		rulebuilder.NoMatch("false positive 2", "BROWSERSTACK_ACCESS_KEY=short"),
		rulebuilder.NoMatch("false positive 3", "BROWSERSTACK_ACCESS_KEY=00000000000000000000"),
	},
})
