package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func Greptile() *config.Rule {
	r := config.Rule{
		RuleID:      "greptile-api-key",
		Description: "Detected a Greptile API Key, which may expose AI-powered code search and analysis services to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"greptile"}, `[a-zA-Z0-9+/]{48}`, true),
		Keywords:    []string{"greptile"},
		Entropy:     3.5,
	}

	tps := []string{
		`greptile_api_key = "Bc4UcqgG6mG5ARxNAOH7TV2C/tDWaB7Kpne/pockv3iQcbSN"`,
		`greptile_api_key = "cRxqPehpNKq5Rtp+QvXBPb6p6n7d+2n4a6dLZqhGQVz2w4ln"`,
		`greptile_api_key = "54tKjWAmKVvnREzrpe4d8/hfgBYf3mpcm/AeKsEHvUnWGx4g"`,
		`greptile = ` + secrets.NewSecret(`[a-zA-Z0-9+/]{48}`),
	}
	fps := []string{
		// Too short
		`greptile_api_key = "Bc4UcqgG6mG5ARxNAOH7TV2C"`,
		// Low entropy (all same chars)
		`greptile_api_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
	}
	return utils.Validate(r, tps, fps)
}
