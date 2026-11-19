package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "yandex-aws-access-token",
	Confidence:  "high",
	Description: "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.",
	Regex:       rulebuilder.Assignment([]string{"yandex"}, `(?i)YC[a-zA-Z0-9_\-]{38}`),
	Keywords: []string{
		"yandex",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `yandexToken = "YCWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_Bdr"`, "YCWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_Bdr"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "yandex-api-key",
	Confidence:  "high",
	Description: "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.",
	Regex:       rulebuilder.Assignment([]string{"yandex"}, `(?i)AQVN[A-Za-z0-9_\-]{35,38}`),
	Keywords: []string{
		"yandex",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `yandexToken = "AQVNWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_"`, "AQVNWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "yandex-access-token",
	Confidence:  "high",
	Description: "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.",
	Regex: rulebuilder.Assignment(
		[]string{"yandex"},
		`(?i)t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2}`,
	),
	Keywords: []string{
		"yandex",
	},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `yandexToken = "t1.E=.v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2"`, "t1.E=.v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2"),
	},
})
