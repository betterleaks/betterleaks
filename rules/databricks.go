package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "databricks-api-token",
	Confidence:  "high",
	Description: "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
	Regex:       rulebuilder.Token(`dapi[a-f0-9]{32}(?:-\d)?`),
	Keywords:    []string{"dapi"},
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `databricksToken = "dapibf5c97d2d2a313e4f95957818a7b3edc"`, "dapibf5c97d2d2a313e4f95957818a7b3edc"),
		rulebuilder.Match("true positive 1", "token = dapif13ac4b49d1cb31f69f678e39602e381-2", "dapif13ac4b49d1cb31f69f678e39602e381-2"),
		rulebuilder.NoMatch("false positive 1", "DATABRICKS_TOKEN=dapi123456789012345678a9bc01234defg5"),
	},
})
