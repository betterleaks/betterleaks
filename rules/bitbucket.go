package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
	ID:          "bitbucket-client-id",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"bitbucket"}, `(?i)[a-z0-9]{32}`),
	Keywords:    []string{"bitbucket"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `bitbucketToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
	ID:          "bitbucket-client-secret",
	Confidence:  "high",
	Regex:       rulebuilder.Assignment([]string{"bitbucket"}, `(?i)[a-z0-9=_\-]{64}`),
	Keywords:    []string{"bitbucket"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `bitbucketToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})

// BBDC- prefix, then base64 of "<token id>:<random bytes>"
var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a Bitbucket Data Center HTTP access token, risking unauthorized repository and project access.",
	ID:          "bitbucket-data-center-token",
	Confidence:  "high",
	Regex:       rulebuilder.Token(`BBDC-[A-Za-z0-9+/=]{32,}`),
	Keywords:    []string{"bbdc"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `BITBUCKET_TOKEN = "BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2F"`, "BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2F"),
		rulebuilder.Match("true positive 2", "token=BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2FFEF7kPYDa7bbPFAv", "BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2FFEF7kPYDa7bbPFAv"),
		rulebuilder.Match("bare secret", "BBDC-ODU3MDkzMTU4MDk1OiKqsM8HOsW1XhaMu33mVB6bLJea", "BBDC-ODU3MDkzMTU4MDk1OiKqsM8HOsW1XhaMu33mVB6bLJea"),
		rulebuilder.NoMatch("false positive 1", `BITBUCKET_TOKEN = "BBDC-XiYBmtb+ICzrn7j7hg5c"`),
		rulebuilder.NoMatch("false positive 2", `bbdc-config-name = "staging"`),
	},
})
