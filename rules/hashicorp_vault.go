package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "vault-service-token",
	Confidence:  "high",
	Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
	Regex:       rulebuilder.Token(`(?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24}))`),
	// `s.` (legacy tokens) appears in over half of all fragments, so gate
	// the rule on `vault` context instead to avoid running the regex
	// everywhere. `hvs.` is precise enough to keep as-is.
	Keywords:   []string{"hvs.", "vault"},
	FilterExpr: "entropy(finding[\"secret\"]) <= 3.5\n|| matchesAny(finding[\"secret\"], [`s\\.[A-Za-z]{24}`])",
	Tests: []config.RuleTest{
		rulebuilder.Match("Old", `vault_api_token = "s.1FbD56TI2smTyVsGd5Xav0yu"`, "s.1FbD56TI2smTyVsGd5Xav0yu"),
		rulebuilder.Match("true positive 1", "vault_token: s.ZC9Ecf4M5g9o34Q6RkzGsj0z", "s.ZC9Ecf4M5g9o34Q6RkzGsj0z"),
		rulebuilder.Match("New", `vault_api_token = "hvs.1E6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2m"`, "hvs.1E6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2m"),
		rulebuilder.Match("longer than 100 chars", `-vaultToken hvs.CAESIP2jTxc9S2K7Z6CtcFWQv7-044m_oSsxnPE1H3nF89l3GiYKHGh2cy5sQmlIZVNyTWJNcDRsYWJpQjlhYjVlb1cQh6PL8wEYAg"`, "hvs.CAESIP2jTxc9S2K7Z6CtcFWQv7-044m_oSsxnPE1H3nF89l3GiYKHGh2cy5sQmlIZVNyTWJNcDRsYWJpQjlhYjVlb1cQh6PL8wEYAg"),
		rulebuilder.NoMatch("word boundary start", "  credentials: new AWS.SharedIniFileCredentials({ profile: '<YOUR_PROFILE>' })"),
		rulebuilder.NoMatch("word boundary end", "INFO 4 --- [           main] o.s.b.f.s.DefaultListableBeanFactory     : Overriding bean definition for bean"),
		rulebuilder.NoMatch("low entropy", "vault: s.xxxxxxxxxxxxxxxxxxxxxxxx"),
		rulebuilder.NoMatch("uppercase", "vault: s.THISSTRINGISALLUPPERCASE"),
		rulebuilder.NoMatch("lowercase", "vault: s.thisstringisalllowercase"),
		rulebuilder.NoMatch("pascal-case", "vault: s.AcceptanceTimeoutSeconds "),
		rulebuilder.NoMatch("camel-case", "vault: s.makeKubeConfigController = args"),
		rulebuilder.NoMatch("low entropy 2", "hvs.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "vault-batch-token",
	Confidence:  "high",
	Description: "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
	Regex:       rulebuilder.Token(`hvb\.[\w-]{138,300}`),
	Keywords:    []string{"hvb."},
	FilterExpr:  `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `vaultToken = "hvb.4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025diy14kz56coijonpywz2z4vn644cqy1nwjur83400pr33be1y409-fl2_aws_vuszepdkvt-2n3y"`, "hvb.4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3pomb2z7epjl8r_uz93d025diy14kz56coijonpywz2z4vn644cqy1nwjur83400pr33be1y409-fl2_aws_vuszepdkvt-2n3y"),
		rulebuilder.Match("bare secret", "hvb.AAAAAQJgxDgqsGNorpoOR7hPZ5SU-ynBvCl764jyRP_fnX7WvkdkDzGjbLNGdPdtlY33Als2P36yDZueqzfdGw9RsaTeaYXSH7E4RYSWuRoQ9YRKIw8o7mDDY2ZcT3KOB7RwtW1w1FN2eDqcy_sbCjXPaM1iBVH-mqMSYRmRd2nb5D1SJPeBzIYRqSglLc31wUGN7xEzyrKUczqOKsIcybQA", "hvb.AAAAAQJgxDgqsGNorpoOR7hPZ5SU-ynBvCl764jyRP_fnX7WvkdkDzGjbLNGdPdtlY33Als2P36yDZueqzfdGw9RsaTeaYXSH7E4RYSWuRoQ9YRKIw8o7mDDY2ZcT3KOB7RwtW1w1FN2eDqcy_sbCjXPaM1iBVH-mqMSYRmRd2nb5D1SJPeBzIYRqSglLc31wUGN7xEzyrKUczqOKsIcybQA"),
	},
})
