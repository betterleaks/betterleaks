package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func MailGunPrivateAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-private-api-token",
		Description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"mailgun"}, `key-[a-f0-9]{32}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("mailgun", "key-"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}

func MailGunPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-pub-key",
		Description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"mailgun"}, `pubkey-[a-f0-9]{32}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("mailgun", "pubkey-"+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}

func MailGunSigningKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-signing-key",
		Description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{"mailgun"}, `[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("mailgun", secrets.NewSecret(utils2.Hex("32"))+"-00001111-22223333")
	return utils2.Validate(r, tps, nil)
}
