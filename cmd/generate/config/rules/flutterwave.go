package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func FlutterwavePublicKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flutterwave-public-key",
		Description: "Detected a Flutterwave Public Key, potentially exposing public cryptographic operations and integrations.",
		Regex:       regexp.MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWPUBK_TEST"},
		Filter:      `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("flutterwavePubKey", "FLWPUBK_TEST-"+secrets.NewSecretWithEntropy(utils.Hex("32"), 2)+"-X")
	return utils.Validate(r, tps, nil)
}

func FlutterwaveSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flutterwave-secret-key",
		Description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWSECK_TEST"},
		Filter:      `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecretWithEntropy(utils.Hex("32"), 2)+"-X")
	return utils.Validate(r, tps, nil)
}

func FlutterwaveEncKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "flutterwave-encryption-key",
		Description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`),
		Keywords:    []string{"FLWSECK_TEST"},
		Filter:      `entropy(finding["secret"]) <= 2.0`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecretWithEntropy(utils.Hex("12"), 2))
	return utils.Validate(r, tps, nil)
}
