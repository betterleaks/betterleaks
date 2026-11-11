package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "browserstack-username.1",
	Confidence:  "medium",
	Description: "BrowserStack username, used as a component of the BrowserStack access-key composite rule.",
	Regex: Assignment(
		[]string{`browserstack[_.-]?(?:username|user)`},
		`[A-Za-z0-9][A-Za-z0-9._-]{2,39}`,
	),
	Keywords:   []string{"browserstack"},
	SkipReport: true,
	FilterExpr: MinEntropy(2.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "BROWSERSTACK_USERNAME=RFbD56TI2smT",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smT"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `browserstack.user: "RFbD56TI2smT"`,
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smT"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "USERNAME=RFbD56TI2smT",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "BROWSERSTACK_USERNAME=ab",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 3",
			Mode:   "match",
			Input:  "BROWSERSTACK_USERNAME=aaaaaaaaaaaa",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "browserstack-access-key.1",
	Confidence:  "high",
	Description: "BrowserStack access key, which may allow access to automated browser and device testing when paired with its username.",
	Regex: Assignment(
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
	FilterExpr: MinEntropy(3.0),
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
		NoMatch("false positive 1", "ACCESS_KEY=RFbD56TI2smTyVsGd5Xa"),
		NoMatch("false positive 2", "BROWSERSTACK_ACCESS_KEY=short"),
		NoMatch("false positive 3", "BROWSERSTACK_ACCESS_KEY=00000000000000000000"),
	},
})
