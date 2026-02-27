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
		Regex:       utils.GenerateSemiGenericRegex([]string{"gitea[_.-]?(?:token|key|secret|access)"}, utils.Hex("40"), true),
		Keywords:    []string{"gitea"},
		Entropy:     3.0,
	}

	tps := utils.GenerateSampleSecrets("gitea", secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		// Too short
		`GITEA_TOKEN=5aab40e433037523cc70af7d3894a0fa`,
		// All zeros (low entropy)
		`GITEA_TOKEN=0000000000000000000000000000000000000000`,
		// Commit SHA near gitea (not a token)
		`gitea/gitea@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0`,
		`Gitea commit: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0`,
	}
	return utils.Validate(r, tps, fps)
}
