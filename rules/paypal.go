package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "paypal-client-id.1",
	Confidence:  "medium",
	Description: "PayPal OAuth client ID, used as a component of the PayPal client-secret composite rule.",
	Regex: Assignment(
		[]string{`paypal[_.-]?(?:client[_.-]?)?(?:id|user)`},
		`A[A-Za-z0-9_-]{78,99}`,
	),
	Keywords:   []string{"paypal"},
	SkipReport: true,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "PAYPAL_CLIENT_ID=AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f",
			Expect: []config.ExpectedFinding{
				{Secret: "AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "CLIENT_ID=AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "PAYPAL_CLIENT_ID=Ashort",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 3",
			Mode:   "match",
			Input:  "PAYPAL_CLIENT_ID=A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			Expect: []config.ExpectedFinding{},
		},
	},
})

// Sandbox and production credentials share their shape. The production
// token endpoint can prove a matching pair valid; a rejection remains
// unknown rather than misclassifying sandbox credentials.
var _ = Add(config.Rule{
	ID:          "paypal-client-secret.1",
	Confidence:  "high",
	Description: "PayPal OAuth client secret, which may allow access to PayPal REST APIs when paired with its client ID.",
	Regex: Assignment(
		[]string{`paypal[_.-]?(?:client[_.-]?)?(?:secret|private|access|key|token)`},
		`[A-Za-z0-9_.-]{78,120}`,
	),
	Keywords: []string{"paypal"},
	Components: []config.Component{
		{RuleID: "paypal-client-id.1", Within: "5L"},
	},
	ValidateExpr: `let r = http.post("https://api-m.paypal.com/v1/oauth2/token", {
    "Authorization": "Basic " + base64.encode(bytes((components["paypal-client-id.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  }, "grant_type=client_credentials"); r.status == 200 && (r.json?.access_token ?? "") != "" ? {
    "result": "valid"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "PAYPAL_CLIENT_SECRET=YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTF\nPAYPAL_CLIENT_ID=AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f",
			Expect: []config.ExpectedFinding{
				{Secret: "YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTF", ComponentSets: []map[string]string{{"paypal-client-id.1": "AWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8f"}}},
			},
		},
		NoMatch("false positive 1", "CLIENT_SECRET=YiZCmtb-JDzrn7j7hg5cgcVBx5xLq3EBscMTKTbcLb2GGFG7kQZEa7bbQGBv9ggrmBcF_Eyrdy5MAe9Xjj0jmpGeTF"),
		NoMatch("false positive 2", "PAYPAL_CLIENT_SECRET=short"),
		NoMatch("false positive 3", "PAYPAL_CLIENT_SECRET=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
	},
})
