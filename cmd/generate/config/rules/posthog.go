package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PostHogProjectAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "posthog-project-api-key",
		Description: "Detected a PostHog Project API Key, which may expose product analytics data and event tracking to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`phc_[a-zA-Z0-9_\-]{43}`, true),
		Keywords:    []string{"phc_"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("posthog", "phc_"+secrets.NewSecret(`[a-zA-Z0-9_\-]{43}`))
	fps := []string{
		// Too short
		`phc_E12345678901234567890123456789012`,
		// Wrong prefix
		`phd_E123456789012345678901234567890123456789012`,
	}
	return utils.Validate(r, tps, fps)
}

func PostHogPersonalAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "posthog-personal-api-key",
		Description: "Detected a PostHog Personal API Key, which may expose administrative access to PostHog analytics projects.",
		Regex:       utils.GenerateUniqueTokenRegex(`phx_[a-zA-Z0-9_\-]{47}`, true),
		Keywords:    []string{"phx_"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("posthog", "phx_"+secrets.NewSecret(`[a-zA-Z0-9_\-]{47}`))
	fps := []string{
		// Too short
		`phx_FNKCx83Ko0JQMuZH1zz94xgK798TCUybkf79ZKYKwKQ`,
		// Wrong prefix
		`phy_FNKCx83Ko0JQMuZH1zz94xgK798TCUybkf79ZKYKwKQWbEw`,
	}
	return utils.Validate(r, tps, fps)
}
