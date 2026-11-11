package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "databricks-api-token",
	Confidence:  "high",
	Description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
	Regex:       Token(`dapi[a-f0-9]{32}(?:-\d)?`),
	Keywords:    []string{"dapi"},
	FilterExpr:  MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("databricks assignment", `databricksToken = "dapibf5c97d2d2a313e4f95957818a7b3edc"`, "dapibf5c97d2d2a313e4f95957818a7b3edc"),
		Match("true positive 1", "token = dapif13ac4b49d1cb31f69f678e39602e381-2", "dapif13ac4b49d1cb31f69f678e39602e381-2"),
		NoMatch("false positive 1", "DATABRICKS_TOKEN=dapi123456789012345678a9bc01234defg5"),
	},
})
