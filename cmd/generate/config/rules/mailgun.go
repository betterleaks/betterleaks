package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func MailGunPrivateAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-private-api-token",
		Description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mailgun"}, `key-[a-f0-9]{32}`, true),

		Keywords: []string{
			"mailgun",
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.mailgun.net/v3/domains", {
    "Accept": "application/json",
    "Authorization": "Basic " + base64.encode(bytes("api:" + finding["secret"]))
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("mailgun", "key-"+secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}

func MailGunPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-pub-key",
		Description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mailgun"}, `pubkey-[a-f0-9]{32}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mailgun", "pubkey-"+secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}

func MailGunSigningKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-signing-key",
		Description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mailgun"}, `[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mailgun", secrets.NewSecret(utils.Hex("32"))+"-00001111-22223333")
	return utils.Validate(r, tps, nil)
}
