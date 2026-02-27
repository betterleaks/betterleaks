package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func EndorLabsAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "endorlabs-api-key",
		Description: "Detected an Endor Labs API Key, which may compromise supply chain security scanning and software composition analysis.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"endor(?:labs)?", "key"}, `endr\+[A-Za-z0-9-]{16}`, true),
		Keywords:    []string{"endr+"},
		Entropy:     3.0,
	}

	tps := []string{
		`ENDOR_API_CREDENTIALS_KEY=endr+` + secrets.NewSecret(`[A-Za-z0-9-]{16}`),
		`endorlabs_api_key=endr+` + secrets.NewSecret(`[A-Za-z0-9-]{16}`),
		`endor_key = "endr+` + secrets.NewSecret(`[A-Za-z0-9-]{16}`) + `"`,
	}
	fps := []string{
		// Wrong secret prefix
		`endorlabs_api_key=endr-foo1234567890abc`,
	}
	return utils.Validate(r, tps, fps)
}

func EndorLabsAPISecret() *config.Rule {
	r := config.Rule{
		RuleID:      "endorlabs-api-secret",
		Description: "Detected an Endor Labs API Secret, which together with an API key grants full access to Endor Labs supply chain security services.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"endor(?:labs)?", "secret"}, `endr\+[A-Za-z0-9-]{16}`, true),
		Keywords:    []string{"endr+"},
		Entropy:     3.5,
	}

	tps := []string{
		`ENDOR_API_CREDENTIALS_SECRET=endr+` + secrets.NewSecret(`[A-Za-z0-9-]{16}`),
		`endorlabs_api_secret=endr+` + secrets.NewSecret(`[A-Za-z0-9-]{16}`),
		`endor_secret = "endr+` + secrets.NewSecret(`[A-Za-z0-9-]{16}`) + `"`,
	}
	fps := []string{
		// Wrong secret prefix
		`endorlabs_api_secret=endr-bar1234567890abc`,
	}
	return utils.Validate(r, tps, fps)
}
