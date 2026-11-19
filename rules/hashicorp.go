package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "hashicorp-tf-api-token",
	Confidence:  "high",
	Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
	Regex:       `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`,
	Keywords:    []string{"atlasv1"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `hashicorpTokenToken = "1f7b169c846f21.atlasv1.ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7"`, "1f7b169c846f21.atlasv1.ki=bm50nvcz3-wjwuth1tchax6992fd-41l48soc903fsrsj9cld-8001fa7"),
		rulebuilder.Match("true positive 1", `#token = "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"`, "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"),
		rulebuilder.NoMatch("low entropy", `token        = "xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "hashicorp-tf-password",
	Confidence:  "medium",
	Description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
	Regex:       rulebuilder.Assignment([]string{"administrator_login_password", "password"}, `(?i)"[a-z0-9=_\-]{8,20}"`),
	Path:        `(?i)\.(?:tf|hcl)$`,
	Keywords:    []string{"administrator_login_password", "password"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		{
			Name:       "true positive 1",
			Input:      `password       = "rootpasswd"`,
			Attributes: map[string]string{"path": "file.hcl"},
			Expect: []config.ExpectedFinding{
				{Secret: `"rootpasswd"`},
			},
		},
		{
			Name:       "true positive 2",
			Input:      `administrator_login_password = "thisIsDog11"`,
			Attributes: map[string]string{"path": "file.tf"},
			Expect: []config.ExpectedFinding{
				{Secret: `"thisIsDog11"`},
			},
		},
		{
			Name:       "false positive 1",
			Input:      `password = "${aws_db_instance.default.password}"`,
			Attributes: map[string]string{"path": "file.hcl"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 2",
			Input:      "administrator_login_password = var.db_password",
			Attributes: map[string]string{"path": "file.tf"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "false positive 3",
			Input:      `password       = "rootpasswd"`,
			Attributes: map[string]string{"path": "unrelated.js"},
			Expect:     []config.ExpectedFinding{},
		},
	},
})
