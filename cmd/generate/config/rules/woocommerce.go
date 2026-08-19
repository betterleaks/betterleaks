package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func WooCommerceConsumerSecret() *config.Rule {
	// WooCommerce stores are self-hosted on customer-controlled domains. Avoid
	// turning an arbitrary nearby store URL into a validation request target.
	r := config.Rule{
		RuleID:      "woocommerce-consumer-secret.1",
		Confidence:  "high",
		Description: "WooCommerce REST API consumer secret, which may allow read or write access to a store with the associated consumer key.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"woo"}, `cs_`+utils.Hex("40"), true),
		Keywords:    []string{"wooc", "woo-", "woo_", "cs_"},
		Filter:      utils.MinEntropy(3.5),
	}

	secret := "cs_" + secrets.NewSecretWithEntropy(`[a-f0-9]{40}`, 3.5)
	tps := utils.GenerateSampleSecrets("woo", secret)
	tps = append(tps,
		`WOO_CONSUMER_SECRET="`+secret+`"`,
		`woo-consumer-secret: `+secret,
	)
	fps := []string{
		`CONSUMER_SECRET=` + secret,
		`WOOCOMMERCE_CONSUMER_KEY=ck_a1b2c3d4e5f60708a9b0c1d2e3f4a5b6c7d8e9f0`,
		`WOOCOMMERCE_CONSUMER_SECRET=cs_short`,
		`WOOCOMMERCE_CONSUMER_SECRET=cs_0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
