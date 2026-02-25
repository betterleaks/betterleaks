package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func GiteaAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "gitea-access-token",
		Description: "Detected a Gitea Access Token, which may expose self-hosted Git repositories and associated code to unauthorized access.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"gitea"}, utils.Hex("40"), true),
		Keywords:    []string{"gitea"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("gitea", secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		// Too short
		`GITEA_TOKEN=5aab40e433037523cc70af7d3894a0fa`,
		// All zeros (low entropy)
		`GITEA_TOKEN=0000000000000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
