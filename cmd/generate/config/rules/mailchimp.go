package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func mailchimpValidation() *config.Validation {
	return &config.Validation{
		Type:   config.ValidationTypeHTTP,
		Method: "GET",
		URL:    `https://{{ secret | split: "-" | last }}.api.mailchimp.com/3.0/ping`,
		Headers: map[string]string{
			"Accept":        "application/json",
			"Authorization": `Basic {{ "x:" | append: secret | b64enc }}`,
		},
		Match: []config.MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
			{StatusCodes: []int{401, 403}, Result: "invalid"},
		},
	}
}

func MailChimp() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailchimp-api-key",
		Description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"MailchimpSDK.initialize", "mailchimp"}, utils.Hex("32")+`-us\d\d`, true),

		Keywords: []string{
			"mailchimp",
		},
		Validation: mailchimpValidation(),
	}

	// validate
	tps := utils.GenerateSampleSecrets("mailchimp", secrets.NewSecret(utils.Hex("32"))+"-us20")
	tps = append(tps,
		`mailchimp_api_key: cefa780880ba5f5696192a34f6292c35-us18`, // gitleaks:allow
		`MAILCHIMPE_KEY = "b5b9f8e50c640da28993e8b6a48e3e53-us18"`, // gitleaks:allow
	)
	fps := []string{
		// False Negative
		`MailchimpSDK.initialize(token: 3012a5754bbd716926f99c028f7ea428-us18)`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
