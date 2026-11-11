package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Discovered a potential Bitbucket Client ID, risking unauthorized repository access and potential codebase exposure.",
	ID:          "bitbucket-client-id",
	Confidence:  "high",
	Regex:       Assignment([]string{"bitbucket"}, `(?i)`+AlphaNumeric("32")),
	Keywords:    []string{"bitbucket"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("bitbucket assignment", `bitbucketToken = "5fbbd6p84oe7ut4qrttebiwar77s63do"`, "5fbbd6p84oe7ut4qrttebiwar77s63do"),
	},
})

var _ = Add(config.Rule{
	Description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
	ID:          "bitbucket-client-secret",
	Confidence:  "high",
	Regex:       Assignment([]string{"bitbucket"}, `(?i)`+AlphaNumericExtended("64")),

	Keywords:   []string{"bitbucket"},
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("bitbucket assignment", `bitbucketToken = "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"`, "5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
	},
})

// BBDC- prefix, then base64 of "<token id>:<random bytes>"
var _ = Add(config.Rule{
	Description: "Discovered a Bitbucket Data Center HTTP access token, risking unauthorized repository and project access.",
	ID:          "bitbucket-data-center-token",
	Confidence:  "high",
	Regex:       Token(`BBDC-[A-Za-z0-9+/=]{32,}`),
	Keywords:    []string{"bbdc"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", `BITBUCKET_TOKEN = "BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2F"`, "BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2F"),
		Match("true positive 2", "token=BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2FFEF7kPYDa7bbPFAv", "BBDC-XiYBmtb+ICzrn7j7hg5cgcUAx5xKq3DAscLSJSbcKb2FFEF7kPYDa7bbPFAv"),
		Match("bare secret", "BBDC-ODU3MDkzMTU4MDk1OiKqsM8HOsW1XhaMu33mVB6bLJea", "BBDC-ODU3MDkzMTU4MDk1OiKqsM8HOsW1XhaMu33mVB6bLJea"),
		NoMatch("false positive 1", `BITBUCKET_TOKEN = "BBDC-XiYBmtb+ICzrn7j7hg5c"`),
		NoMatch("false positive 2", `bbdc-config-name = "staging"`),
	},
})
