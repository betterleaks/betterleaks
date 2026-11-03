package rules

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func HashiCorpTerraform() *config.Rule {
	// define rule
	r := config.Rule{
		ID:          "hashicorp-tf-api-token",
		Confidence:  "high",
		Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
		Regex:       `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`,
		Keywords:    []string{"atlasv1"},
		FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("hashicorpToken", secrets.NewSecret(utils.Hex("14"))+".atlasv1."+secrets.NewSecretWithEntropy(utils.AlphaNumericExtended("60,70"), 3.5))
	tps = append(tps,
		`#token = "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"`,
	)
	fps := []string{
		`token        = "xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // low entropy
	}
	return utils.Validate(r, tps, fps)
}

func HashicorpField() *config.Rule {
	keywords := []string{"administrator_login_password", "password"}
	inlinePasswordRegex := utils.GenerateSemiGenericRegex(keywords, fmt.Sprintf(`"%s"`, utils.AlphaNumericExtended("8,20")), true)
	variableBody := `(?:#[^\r\n]*|//[^\r\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|[^{}"])*?`
	for range 4 {
		variableBody = `(?:#[^\r\n]*|//[^\r\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|[^{}"]|\{` + variableBody + `\})*?`
	}
	variableDefaultPasswordRegex := fmt.Sprintf(
		`(?im)\bvariable\s+"(?:%s)"\s*\{%s^[ \t]*default[ \t]*=[ \t]*("[a-z0-9=_\-]{8,}")[ \t]*\r?(?://[^\r\n]*|#[^\r\n]*)?$`,
		strings.Join(keywords, "|"), variableBody,
	)
	// define rule
	r := config.Rule{
		ID:          "hashicorp-tf-password",
		Confidence:  "medium",
		Description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
		Regex:       fmt.Sprintf(`(?:%s)|(?:%s)`, inlinePasswordRegex, variableDefaultPasswordRegex),
		Path:        `(?i)\.(?:tf|hcl)$`,
		Keywords:    keywords,
		FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	}

	tps := map[string]string{
		// Example from: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server.html
		"file.tf": "administrator_login_password = " + `"thisIsDog11"`,
		// https://registry.terraform.io/providers/petoju/mysql/latest/docs
		"file.hcl": "password       = " + `"rootpasswd"`,
		"variables.tf": `variable "password" {
  type    = string
  default = "A1b2C3d4E5f6G7h8I9j0K1l2M3"
}`,
	}
	fps := map[string]string{
		"file.tf":        "administrator_login_password = var.db_password",
		"file.hcl":       `password = "${aws_db_instance.default.password}"`,
		"unrelated.js":   "password       = " + `"rootpasswd"`,
		"variables.tf":   "variable \"username\" {\n  default = \"rootpasswd\"\n}",
		"expression.tf":  "variable \"password\" {\n  default = var.db_password\n}",
		"unrelated.yaml": "variable \"password\" {\n  default = \"rootpasswd\"\n}",
	}

	return utils.ValidateWithPaths(r, tps, fps)
}
