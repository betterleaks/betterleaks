package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func FlutterwavePublicKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flutterwave-public-key",
		Description: "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.",
		Regex:       regexp.MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`),
		Entropy:     2,
		Keywords:    []string{"FLWPUBK_TEST"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("flutterwavePubKey", "FLWPUBK_TEST-"+secrets.NewSecret(utils2.Hex("32"))+"-X")
	return utils2.Validate(r, tps, nil)
}

func FlutterwaveSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flutterwave-secret-key",
		Description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`),
		Entropy:     2,
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecret(utils2.Hex("32"))+"-X")
	return utils2.Validate(r, tps, nil)
}

func FlutterwaveEncKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flutterwave-encryption-key",
		Description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`),
		Entropy:     2,
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecret(utils2.Hex("12")))
	return utils2.Validate(r, tps, nil)
}
