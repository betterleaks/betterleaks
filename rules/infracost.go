package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "infracost-api-token",
	Confidence:  "high",
	Description: "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",
	Regex:       Token(`ico-[a-zA-Z0-9]{32}`),
	Keywords:    []string{"ico-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("ico assignment", `icoToken = "ico-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"`, "ico-RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA"),
		Match("true positive 1", "  variable {\n    name = \"INFRACOST_API_KEY\"\n    secret_value = \"ico-mlCr1Mn3SRcRiZMObUZOTHLcgtH2Lpgt\"\n    is_secret = true\n  }", "ico-mlCr1Mn3SRcRiZMObUZOTHLcgtH2Lpgt"),
		NoMatch("Low entropy", "ico-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
		NoMatch("Invalid", "http://assets.r7.com/assets/media_box_tv_tres_colunas/video_box.ico-7a388b69018576d24b59331fd60aab0c.png"),
		NoMatch("false positive 1", "https://explosivelab.notion.site/Pianificazione-Nerdz-Ng-pubblico-1bc826ecc0994dd8915be97fc3489cde?pvs=74"),
		NoMatch("false positive 2", "http://ece252-2.uwaterloo.ca:2540/image?q=gAAAAABdHkoqb9ZaJ3q4dlzEvTgG9WYwKcD9Aw7OUXeFicO-5M5IdNDjHBpKw7KBK3nCVqtuga4yzUaFEpJn8BqA1LzZprIJBw=="),
	},
})
