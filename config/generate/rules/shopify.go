package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func ShopifySharedSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shopify-shared-secret",
		Description: "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
		Regex:       regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		Entropy:     2,
		Keywords:    []string{"shpss_"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("shopify", "shpss_"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}

func ShopifyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shopify-access-token",
		Description: "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.",
		Regex:       regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		Entropy:     2,
		Keywords:    []string{"shpat_"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("shopify", "shpat_"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}

func ShopifyCustomAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shopify-custom-access-token",
		Description: "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
		Regex:       regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`),
		Entropy:     2,
		Keywords:    []string{"shpca_"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("shopify", "shpca_"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}

func ShopifyPrivateAppAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shopify-private-app-access-token",
		Description: "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.",
		Regex:       regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`),
		Entropy:     2,
		Keywords:    []string{"shppa_"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("shopify", "shppa_"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}
