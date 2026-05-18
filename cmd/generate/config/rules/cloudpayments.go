package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func CloudPaymentsAPISecret() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudpayments-api-secret",
		Description: "Detected a CloudPayments API secret key, which may expose access to payment processing services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"cloudpayments"}, `[a-z0-9]{32,64}`, true),
		Keywords:    []string{"cloudpayments"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("cloudpayments", secrets.NewSecretWithEntropy(`[a-z0-9]{32,64}`, 3.5))
	fps := []string{
		`cloudpayments_checkout_url = "https://pay.cloudpayments.ru"`,
		`cloudpayments_public_id = "pk_test_1234"`,
	}
	return utils.Validate(r, tps, fps)
}
