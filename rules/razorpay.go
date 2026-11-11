package rules

import "github.com/betterleaks/betterleaks/v2/config"

// Razorpay key IDs are intentionally used in client-side integrations and
// are not confidential. They only gate and validate the associated secret.
var _ = Add(config.Rule{
	ID:          "razorpay-key-id.1",
	Confidence:  "high",
	Description: "Razorpay key ID, used as a component of the Razorpay key-secret composite rule.",
	Regex:       Token(`rzp_(?:live|test)_[A-Za-z0-9]{14}`),
	Keywords:    []string{"rzp_live_", "rzp_test_"},
	SkipReport:  true,
	FilterExpr:  MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "RAZORPAY_KEY_ID=rzp_live_RFbD56TI2smTyV",
			Expect: []config.ExpectedFinding{
				{Secret: "rzp_live_RFbD56TI2smTyV"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `razorpay_key_id: "rzp_test_RFbD56TI2smTyV"`,
			Expect: []config.ExpectedFinding{
				{Secret: "rzp_test_RFbD56TI2smTyV"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "RAZORPAY_KEY_ID=rzp_live_short",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "RAZORPAY_KEY_ID=rzp_live_00000000000000",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 3",
			Mode:   "match",
			Input:  "RAZORPAY_KEY_ID=rzp_demo_AbCdEf12345678",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "razorpay-key-secret.1",
	Confidence:  "high",
	Description: "Razorpay key secret, which may authorize payment APIs when paired with its key ID.",
	Regex: Assignment(
		[]string{`razorpay[_.-]?(?:(?:api|key)[_.-]?)?(?:secret|private|token)`},
		`[A-Za-z0-9]{24}`,
	),
	Keywords: []string{"razorpay"},
	Components: []config.Component{
		{RuleID: "razorpay-key-id.1", Within: "5L"},
	},
	ValidateExpr: `let r = http.get("https://api.razorpay.com/v1/items?count=1", {
    "Authorization": "Basic " + base64.encode(bytes((components["razorpay-key-id.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"items\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid Razorpay key ID or secret"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "RAZORPAY_KEY_SECRET=RFbD56TI2smTyVsGd5Xav0yu\nRAZORPAY_KEY_ID=rzp_live_RFbD56TI2smTyV",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smTyVsGd5Xav0yu", ComponentSets: []map[string]string{{"razorpay-key-id.1": "rzp_live_RFbD56TI2smTyV"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "razorpay.api_secret: \"RFbD56TI2smTyVsGd5Xav0yu\"\nRAZORPAY_KEY_ID=rzp_live_RFbD56TI2smTyV",
			Expect: []config.ExpectedFinding{
				{Secret: "RFbD56TI2smTyVsGd5Xav0yu", ComponentSets: []map[string]string{{"razorpay-key-id.1": "rzp_live_RFbD56TI2smTyV"}}},
			},
		},
		NoMatch("false positive 1", "KEY_SECRET=RFbD56TI2smTyVsGd5Xav0yu"),
		NoMatch("false positive 2", "RAZORPAY_KEY_SECRET=short"),
		NoMatch("false positive 3", "RAZORPAY_KEY_SECRET=000000000000000000000000"),
	},
})
