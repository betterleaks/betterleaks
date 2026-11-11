package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "octopus-deploy-api-key",
	Confidence:  "medium",
	Description: "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
	Regex:       Token(`API-[A-Z0-9]{26}`),
	Keywords:    []string{"api-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("true positive 1", `octopus_api_token = "API-5FBBD6P84OE7UT4QRTTEBIWAR7"`, "API-5FBBD6P84OE7UT4QRTTEBIWAR7"),
		Match("true positive 2", `set apikey="API-ZNRMR7SL6L3ATMOIK7GKJDKLPY"`, "API-ZNRMR7SL6L3ATMOIK7GKJDKLPY"),
		NoMatch("Invalid start", `msgstr "GSSAPI-VIRHEKAPSELOINTIMERKKIJONO."`),
		NoMatch("false positive 1", "https://sonarcloud.io/api/project_badges/measure?project=Garden-Coin_API-CalculadoraDeInvestimentos&metric=alert_status"),
		NoMatch("Invalid end", "https://fog-ringer-f42.notion.site/API-BD80F56CDC1441E6BF6011AB6D852875"),
		NoMatch("Wrong case", `<iframe src="./archive/gifs/api-c99e353f761d318322c853c03e.gif"> </iframe>`),
	},
})
