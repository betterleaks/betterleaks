package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
	"github.com/betterleaks/betterleaks/regexp"
)

func HashiCorpTerraform() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "hashicorp-tf-api-token",
		Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
		Regex:       regexp.MustCompile(`(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`),
		Entropy:     3.5,
		Keywords:    []string{"atlasv1"},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("hashicorpToken", secrets.NewSecret(utils2.Hex("14"))+".atlasv1."+secrets.NewSecret(utils2.AlphaNumericExtended("60,70")))
	tps = append(tps,
		`#token = "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"`,
	)
	fps := []string{
		`token        = "xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // low entropy
	}
	return utils2.Validate(r, tps, fps)
}

func HashicorpField() *config.Rule {
	keywords := []string{"administrator_login_password", "password"}
	// define rule
	r := config.Rule{
		RuleID:      "hashicorp-tf-password",
		Description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
		Regex:       utils2.GenerateSemiGenericRegex(keywords, fmt.Sprintf(`"%s"`, utils2.AlphaNumericExtended("8,20")), true),
		Entropy:     2,
		Path:        regexp.MustCompile(`(?i)\.(?:tf|hcl)$`),
		Keywords:    keywords,
	}

	tps := map[string]string{
		// Example from: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server.html
		"file.tf": "administrator_login_password = " + `"thisIsDog11"`,
		// https://registry.terraform.io/providers/petoju/mysql/latest/docs
		"file.hcl": "password       = " + `"rootpasswd"`,
	}
	fps := map[string]string{
		"file.tf":      "administrator_login_password = var.db_password",
		"file.hcl":     `password = "${aws_db_instance.default.password}"`,
		"unrelated.js": "password       = " + `"rootpasswd"`,
	}

	return utils2.ValidateWithPaths(r, tps, fps)
}
