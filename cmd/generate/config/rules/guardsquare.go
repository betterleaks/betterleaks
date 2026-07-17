package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GuardSquareAppSweepAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "guardsquare-appsweep-api-key",
		Description: "GuardSquare AppSweep API key.",
		Regex:       regexp.MustCompile(`\b(gs_appsweep_[a-zA-Z0-9_-]{24,48})`),
		Keywords:    []string{"gs_appsweep_"},
		Filter:      utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("guardsquare", "gs_appsweep_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_-]{32}`, 3.0)),
	}
	fps := []string{
		`gs_appsweep_short`,
	}
	return utils.Validate(r, tps, fps)
}
