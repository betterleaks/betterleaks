package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func VercelAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-api-token",
		Description: "Detected a Vercel API Token, which may expose deployment and serverless infrastructure to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"vercel"}, `[A-Z0-9]{24}`, true),
		Keywords:    []string{"vercel"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("vercel", secrets.NewSecret(`[A-Z0-9]{24}`))
	fps := []string{
		// Too short
		`vercel_key = DdZV6ZDZW6Vpl7n7Jq`,
		// All same chars (low entropy)
		`vercel_key = AAAAAAAAAAAAAAAAAAAAAAAA`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelPersonalAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-personal-access-token",
		Description: "Detected a Vercel Personal Access Token (vcp_), which may expose full account and deployment management capabilities.",
		Regex:       utils.GenerateUniqueTokenRegex(`vcp_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vcp_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vcp_"+secrets.NewSecret(`[A-Za-z0-9_-]{56}`))
	fps := []string{
		// Too short
		`vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHe`,
		// Wrong prefix
		`vct_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelIntegrationToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-integration-token",
		Description: "Detected a Vercel Integration Token (vci_), which may allow third-party service integrations to act on behalf of users.",
		Regex:       utils.GenerateUniqueTokenRegex(`vci_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vci_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vci_"+secrets.NewSecret(`[A-Za-z0-9_-]{56}`))
	fps := []string{
		// Too short
		`vci_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHe`,
		// Wrong prefix
		`vcp_35UYJwYZDigYATKhxJUAhPqRhit2Xe3dtiG60LsUTHeklEXDQ94Jafpu`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelAppAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-app-access-token",
		Description: "Detected a Vercel App Access Token (vca_), which may allow Sign in with Vercel apps to access user resources.",
		Regex:       utils.GenerateUniqueTokenRegex(`vca_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vca_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vca_"+secrets.NewSecret(`[A-Za-z0-9_-]{56}`))
	fps := []string{
		// Too short
		`vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0t`,
		// Wrong prefix
		`vcb_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelAppRefreshToken() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-app-refresh-token",
		Description: "Detected a Vercel App Refresh Token (vcr_), which may allow persistent unauthorized access through token refresh flows.",
		Regex:       utils.GenerateUniqueTokenRegex(`vcr_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vcr_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vcr_"+secrets.NewSecret(`[A-Za-z0-9_-]{56}`))
	fps := []string{
		// Too short
		`vcr_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0t`,
		// Wrong prefix
		`vcp_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz`,
	}
	return utils.Validate(r, tps, fps)
}

func VercelAIGatewayKey() *config.Rule {
	r := config.Rule{
		RuleID:      "vercel-ai-gateway-key",
		Description: "Detected a Vercel AI Gateway API Key (vck_), which may expose AI model routing and gateway access to unauthorized parties.",
		Regex:       utils.GenerateUniqueTokenRegex(`vck_[A-Za-z0-9_-]{56}`, true),
		Keywords:    []string{"vck_"},
		Entropy:     3.5,
	}

	tps := utils.GenerateSampleSecrets("vercel", "vck_"+secrets.NewSecret(`[A-Za-z0-9_-]{56}`))
	fps := []string{
		// Too short
		`vck_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4t`,
		// Wrong prefix
		`vcp_2YkmQj1uHqCVNoUx5a9uvRTe81gmAcln5hoRMPWFBU4tulufUf0OzP2K`,
	}
	return utils.Validate(r, tps, fps)
}
