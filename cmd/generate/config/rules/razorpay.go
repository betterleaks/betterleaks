package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func RazorpayKeyID() *config.Rule {
	// Razorpay key IDs are intentionally used in client-side integrations and
	// are not confidential. They only gate and validate the associated secret.
	r := config.Rule{
		RuleID:      "razorpay-key-id.1",
		Confidence:  "high",
		Description: "Razorpay key ID, used as a component of the Razorpay key-secret composite rule.",
		Regex:       utils.GenerateUniqueTokenRegex(`rzp_(?:live|test)_[A-Za-z0-9]{14}`, false),
		Keywords:    []string{"rzp_live_", "rzp_test_"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(3.0),
	}

	keyID := "rzp_live_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{14}`, 3.0)
	testKeyID := "rzp_test_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{14}`, 3.0)
	tps := []string{
		`RAZORPAY_KEY_ID=` + keyID,
		`razorpay_key_id: "` + testKeyID + `"`,
	}
	fps := []string{
		`RAZORPAY_KEY_ID=rzp_live_short`,
		`RAZORPAY_KEY_ID=rzp_live_00000000000000`,
		`RAZORPAY_KEY_ID=rzp_demo_AbCdEf12345678`,
	}
	return utils.Validate(r, tps, fps)
}

func RazorpayKeySecret() *config.Rule {
	r := config.Rule{
		RuleID:      "razorpay-key-secret.1",
		Confidence:  "high",
		Description: "Razorpay key secret, which may authorize payment APIs when paired with its key ID.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`razorpay[_.-]?(?:(?:api|key)[_.-]?)?(?:secret|private|token)`},
			`[A-Za-z0-9]{24}`,
			false,
		),
		Keywords: []string{"razorpay"},
		Components: []*config.Component{
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
		Filter: utils.MinEntropy(3.0),
	}

	keySecret := secrets.NewSecretWithEntropy(`[A-Za-z0-9]{24}`, 3.0)
	tps := []string{
		`RAZORPAY_KEY_SECRET=` + keySecret,
		`razorpay.api_secret: "` + keySecret + `"`,
	}
	fps := []string{
		`KEY_SECRET=` + keySecret,
		`RAZORPAY_KEY_SECRET=short`,
		`RAZORPAY_KEY_SECRET=000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
