package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "microsoft-teams-webhook",
	Confidence:  "high",
	Description: "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.",
	Regex:       `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`,
	Keywords: []string{
		"webhook.office.com",
		"webhookb2",
		"IncomingWebhook",
	},
	Tests: []config.RuleTest{
		Match("true positive 1", "https://mycompany.webhook.office.com/webhookb2/5fbbd6p8-4oe7-ut4q-rtte-biwar77s63do@nnl8x7li-pmar-1rys-jl9p-9f4p8u7nz6lc/IncomingWebhook/a8hqn2j0qefi1vg8f9p1t7tnza246j0v/crp2lv3h-n2ad-us61-vq0d-nd3i2a93m65m", "rtte-"),
	},
})
