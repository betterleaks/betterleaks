package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "salesforce-instance-url.1",
	Confidence:  "high",
	Description: "Salesforce instance host, used as a component of the Salesforce access-token rule.",
	Regex:       `(?i)(?:^|[^a-z0-9.-])(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){0,4}\.my\.salesforce\.com|[a-z]{2,8}[0-9]{1,4}\.salesforce\.com))(?:[^a-z0-9.-]|$)`,
	Keywords:    []string{"salesforce.com"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com",
			Expect: []config.ExpectedFinding{
				{Secret: "example123.my.salesforce.com"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: "SALESFORCE_INSTANCE_URL=https://acme--dev.sandbox.my.salesforce.com",
			Expect: []config.ExpectedFinding{
				{Secret: "acme--dev.sandbox.my.salesforce.com"},
			},
		},
		{
			Name:  "true positive 3",
			Mode:  "match",
			Input: "SALESFORCE_INSTANCE_URL=https://na123.salesforce.com",
			Expect: []config.ExpectedFinding{
				{Secret: "na123.salesforce.com"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "SALESFORCE_INSTANCE_URL=https://example.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "SALESFORCE_INSTANCE_URL=https://-invalid.my.salesforce.com",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 3",
			Mode:   "match",
			Input:  "SALESFORCE_INSTANCE_URL=https://my.salesforce.com.evil.example",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "salesforce-access-token.1",
	Confidence:  "high",
	Description: "Salesforce access token.",
	Regex:       Token(`00[A-Za-z0-9]{13}![A-Za-z0-9._-]{80,260}`),
	Keywords:    []string{"salesforce.com"},
	Components: []config.Component{
		{RuleID: "salesforce-instance-url.1", Within: "30L"},
	},
	ValidateExpr: `let r = http.get("https://" + (components["salesforce-instance-url.1"]?.secret ?? "") + "/services/data/v67.0/limits", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"DailyApiRequests\"") ? {
    "result": "valid"
  } : r.status == 403 && (r.body contains "\"REQUEST_LIMIT_EXCEEDED\"") ? {
    "result": "valid",
    "reason": "Authenticated but the organization API request limit is exceeded"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.3),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00RFbD56TI2smTy!YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTFtm.U-G",
			Expect: []config.ExpectedFinding{
				{Secret: "00RFbD56TI2smTy!YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTFtm.U-G", ComponentSets: []map[string]string{{"salesforce-instance-url.1": "example123.my.salesforce.com"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "=== Org Description\nAccess Token      00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLEzmpkb58urFRkgeBGsxL_QJWwYMfAbUeeG7c1EXAMPLEDUkWe6H34r1AAwOR8B8fLEz6nEXAMPLEAAAA\nInstance Url      https://MyDomainName.my.salesforce.com",
			Expect: []config.ExpectedFinding{
				{Secret: "00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLEzmpkb58urFRkgeBGsxL_QJWwYMfAbUeeG7c1EXAMPLEDUkWe6H34r1AAwOR8B8fLEz6nEXAMPLEAAAA", ComponentSets: []map[string]string{{"salesforce-instance-url.1": "MyDomainName.my.salesforce.com"}}},
			},
		},
		NoMatch("false positive 1", "SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00DE0X0A0M0PeLE!short"),
		NoMatch("false positive 2", "SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00DE0X0A0M0PeLE!xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		NoMatch("false positive 3", "SALESFORCE_INSTANCE_URL=https://example123.my.salesforce.com\nSALESFORCE_ACCESS_TOKEN=00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLEzmpkb58urFRkgeBGsxL/QJWwYMfAbUeeG7c1EXAMPLEDUkWe6H34r1AAwOR8B8fLEz6nEXAMPLEAAAA"),
	},
})
