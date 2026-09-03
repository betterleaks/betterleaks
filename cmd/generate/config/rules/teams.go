package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

func TeamsWebhook() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "microsoft-teams-webhook",
		Confidence:  "high",
		Description: "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.",
		Regex: regexp.MustCompile(
			`https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`),
		Keywords: []string{
			"webhook.office.com",
			"webhookb2",
			"IncomingWebhook",
		},
	}

	// validate
	tps := []string{
		"https://mycompany.webhook.office.com/webhookb2/" + secrets.NewSecret(`[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`), // gitleaks:allow
	}
	return utils.Validate(r, tps, nil)
}
