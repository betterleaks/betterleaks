package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
	ID:          "heroku-api-key",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"heroku"}, `(?i)`+rulebuilder.Hex8_4_4_4_12()),
	Keywords:    []string{"heroku"},
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `herokuToken = "1f7b169c-846f-218a-b552-fa82fbf86758"`, "1f7b169c-846f-218a-b552-fa82fbf86758"),
		rulebuilder.Match("true positive 1", `const HEROKU_KEY = "12345678-ABCD-ABCD-ABCD-1234567890AB"`, "12345678-ABCD-ABCD-ABCD-1234567890AB"),
		rulebuilder.Match("true positive 2", `heroku_api_key = "832d2129-a846-4e27-99f4-7004b6ad53ef"`, "832d2129-a846-4e27-99f4-7004b6ad53ef"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
	ID:          "heroku-api-key-v2",
	Confidence:  "high",
	Regex:       rulebuilder.Token(`(HRKU-AA[0-9a-zA-Z_-]{58})`),
	Keywords:    []string{"hrku-aa"},
	FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `herokuToken = "HRKU-AAWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7u"`, "HRKU-AAWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7u"),
		rulebuilder.Match("true positive 1", `const KEY = "HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzhoERRSO45ZQusSYHg_____w4_hLrAym_u""`, "HRKU-AAlQ1aVoHDujJ9QsDHdHlHO0hbzhoERRSO45ZQusSYHg_____w4_hLrAym_u"),
		rulebuilder.Match("true positive 2", `API_Key = "HRKU-AAy9Ppr_HD2pPuTyIiTYInO0hbzhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX"`, "HRKU-AAy9Ppr_HD2pPuTyIiTYInO0hbzhoERRSO93ZQusSYHgaD7_WQ07FnF7L9FX"),
	},
})
