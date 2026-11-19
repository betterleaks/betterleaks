package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "gitea-access-token",
	Confidence:  "high",
	Description: "Detected a Gitea Access Token, which may expose self-hosted Git repositories and associated code to unauthorized access.",
	Regex:       rulebuilder.Assignment([]string{"gitea[_.-]?(?:token|key|secret|access)"}, `(?i)[a-f0-9]{40}`),
	Keywords:    []string{"gitea"},
	FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `giteaToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2"),
		rulebuilder.NoMatch("Too short", "GITEA_TOKEN=5aab40e433037523cc70af7d3894a0fa"),
		rulebuilder.NoMatch("All zeros (low entropy)", "GITEA_TOKEN=0000000000000000000000000000000000000000"),
		rulebuilder.NoMatch("Commit SHA near gitea (not a token)", "gitea/gitea@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
		rulebuilder.NoMatch("false positive 1", "Gitea commit: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"),
	},
})
