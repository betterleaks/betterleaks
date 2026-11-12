package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "okta-access-token",
	Confidence:  "high",
	Description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
	Regex:       rulebuilder.Assignment([]string{`(?-i:[Oo]kta|OKTA)`}, `00[\w=\-]{40}`),
	Keywords: []string{
		"okta",
	},
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `oktaToken = "00YiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbc"`, "00YiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbc"),
		rulebuilder.Match("true positive 1", `"oktaApiToken": "00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3",`, "00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3"),
		rulebuilder.Match("true positive 2", "\t\t\tvar OktaApiToken = \"00fWkOjwwL9xiFd-Vfgm_ePATIRxVj852Iblbb1DS_\";", "00fWkOjwwL9xiFd-Vfgm_ePATIRxVj852Iblbb1DS_"),
		rulebuilder.NoMatch("low entropy", "oktaKey = 00000000000000000000000000000000000TUVWXYZ"),
		rulebuilder.NoMatch("wrong case", "rookTable = 0023452Lllk2KqjLBvaxANWEgTd7bqjsxjo8aZj0wd"),
	},
})

// TODO: Okta client secret?
