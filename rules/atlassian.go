package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Detected an Atlassian Cloud API token, posing a threat to project management and collaboration tool security and data confidentiality.",
	ID:          "atlassian-api-token",
	Confidence:  "high",
	Regex:       rulebuilder.Token(`ATAT[A-Za-z0-9_\-=]{100,}`),
	Keywords:    []string{"atat"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `ATLASSIAN_API_TOKEN="ATATT3YiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtIGbmSKx-X-XFLe0FzsdAEprxYCO9jEz=1ggNUHQoaBaUZZJa9Orr9wMW9jr41QUOG8ZBsteVT4vNaPA4mC4ob8vG"`, "ATATT3YiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtIGbmSKx-X-XFLe0FzsdAEprxYCO9jEz=1ggNUHQoaBaUZZJa9Orr9wMW9jr41QUOG8ZBsteVT4vNaPA4mC4ob8vG"),
		rulebuilder.Match("true positive 2", "token=ATATYiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtIG", "ATATYiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtIG"),
		rulebuilder.NoMatch("false positive 1", "JIRA_API_TOKEN=HXe8DGg1iJd2AopzyxkFB7F2"),
		rulebuilder.NoMatch("false positive 2", "BITBUCKET_ACCESS_TOKEN=ATCTYiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtIG"),
		rulebuilder.NoMatch("false positive 3", "BITBUCKET_APP_PASSWORD=ATBBYiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtIG"),
		rulebuilder.NoMatch("false positive 4", "ATLASSIAN_API_TOKEN=ATATYiZCmtb-JDzrn8j8hg6cgcVBx6xLq4EBscMTKTbcLb3GGFG8kQZEa8bbQGBv=ggrmBcF_Eyrdy6MAe=Xjj1jmpGeTFtm0U-GFtI"),
		rulebuilder.NoMatch("false positive 5", "getPagesInConfluenceSpace,searchConfluenceUsingCql"),
	},
})
