package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func Atlassian() *config.Rule {
	r := config.Rule{
		Description: "Detected an Atlassian Cloud API token, posing a threat to project management and collaboration tool security and data confidentiality.",
		RuleID:      "atlassian-api-token",
		Confidence:  "high",
		Regex:       utils.GenerateUniqueTokenRegex(`ATAT[A-Za-z0-9_\-=]{100,}`, false),
		Keywords:    []string{"atat"},
		Filter:      `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	currentToken := "ATATT3" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-=]{186}`, 3.5)
	variableToken := "ATAT" + secrets.NewSecretWithEntropy(`[A-Za-z0-9_\-=]{100}`, 3.5)
	tps := []string{
		`ATLASSIAN_API_TOKEN="` + currentToken + `"`,
		`token=` + variableToken,
	}

	fps := []string{
		`JIRA_API_TOKEN=HXe8DGg1iJd2AopzyxkFB7F2`,
		`BITBUCKET_ACCESS_TOKEN=ATCT` + secrets.NewSecret(`[A-Za-z0-9_\-=]{100}`),
		`BITBUCKET_APP_PASSWORD=ATBB` + secrets.NewSecret(`[A-Za-z0-9_\-=]{100}`),
		`ATLASSIAN_API_TOKEN=ATAT` + secrets.NewSecret(`[A-Za-z0-9_\-=]{99}`),
		`getPagesInConfluenceSpace,searchConfluenceUsingCql`,
	}

	return utils.Validate(r, tps, fps)
}
