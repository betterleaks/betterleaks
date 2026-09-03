package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func PayPalClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "paypal-client-id.1",
		Confidence:  "medium",
		Description: "PayPal OAuth client ID, used as a component of the PayPal client-secret composite rule.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`paypal[_.-]?(?:client[_.-]?)?(?:id|user)`},
			`A[A-Za-z0-9_-]{78,99}`,
			false,
		),
		Keywords:   []string{"paypal"},
		SkipReport: true,
		Filter:     utils.MinEntropy(3.5),
	}

	clientID := "A" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{86}`, 3.5)
	tps := []string{
		`PAYPAL_CLIENT_ID=` + clientID,
	}
	fps := []string{
		`CLIENT_ID=` + clientID,
		`PAYPAL_CLIENT_ID=Ashort`,
		`PAYPAL_CLIENT_ID=A00000000000000000000000000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func PayPalClientSecret() *config.Rule {
	// Sandbox and production credentials share their shape. The production
	// token endpoint can prove a matching pair valid; a rejection remains
	// unknown rather than misclassifying sandbox credentials.
	r := config.Rule{
		RuleID:      "paypal-client-secret.1",
		Confidence:  "high",
		Description: "PayPal OAuth client secret, which may allow access to PayPal REST APIs when paired with its client ID.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`paypal[_.-]?(?:client[_.-]?)?(?:secret|private|access|key|token)`},
			`[A-Za-z0-9_.-]{78,120}`,
			false,
		),
		Keywords: []string{"paypal"},
		Components: []*config.Component{
			{RuleID: "paypal-client-id.1", Within: "5L"},
		},
		ValidateExpr: `let r = http.post("https://api-m.paypal.com/v1/oauth2/token", {
    "Authorization": "Basic " + base64.encode(bytes((components["paypal-client-id.1"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
  }, "grant_type=client_credentials"); r.status == 200 && (r.json?.access_token ?? "") != "" ? {
    "result": "valid"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	clientSecret := secrets.NewSecretWithEntropy(`[A-Za-z0-9_.-]{90}`, 3.5)
	tps := []string{
		`PAYPAL_CLIENT_SECRET=` + clientSecret,
	}
	fps := []string{
		`CLIENT_SECRET=` + clientSecret,
		`PAYPAL_CLIENT_SECRET=short`,
		`PAYPAL_CLIENT_SECRET=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
