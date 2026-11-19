package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "docker-swarm-join-token",
	Confidence:  "high",
	Description: "Docker Swarm join token.",
	Regex:       `\b(SWMTKN-1-[a-z0-9]{50,60}-[a-z0-9]{24,30})`,
	Keywords:    []string{"swmtkn-1-"},
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "docker swarm join --token SWMTKN-1-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl-5fbbd6p84oe7ut4qrttebiwa", "SWMTKN-1-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl-5fbbd6p84oe7ut4qrttebiwa"),
		rulebuilder.NoMatch("false positive 1", "SWMTKN-1-short"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "docker-swarm-unlock-key",
	Confidence:  "high",
	Description: "Docker Swarm unlock key.",
	Regex:       `\b(SWMKEY-1-[A-Za-z0-9+/]{40,50})`,
	Keywords:    []string{"swmkey-1-"},
	FilterExpr:  rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "docker swarm unlock --key SWMKEY-1-VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG", "SWMKEY-1-VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"),
		rulebuilder.NoMatch("false positive 1", "SWMKEY-1-short"),
	},
})
