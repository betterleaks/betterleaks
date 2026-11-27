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

var _ = rulebuilder.Add(config.Rule{
	ID:          "databricks-oauth-secret",
	Confidence:  "high",
	Description: "Uncovered a Databricks OAuth client secret, which may allow a service principal to access Databricks workspaces and accounts.",
	Regex:       rulebuilder.Token(`dose[a-z0-9]{32}`),
	Keywords:    []string{"dose"},
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `DATABRICKS_CLIENT_SECRET = "dose4f8a1c9e2b7d3a6f0e5c8b1d9a2f7e4c"`, "dose4f8a1c9e2b7d3a6f0e5c8b1d9a2f7e4c"),
		rulebuilder.Match("env file", "client_secret=dosea7k2m9p4q8r1s5t3v6w0x2y7z4b9c1d8", "dosea7k2m9p4q8r1s5t3v6w0x2y7z4b9c1d8"),
		rulebuilder.NoMatch("too short", "client_secret=dose4f8a1c9e2b7d3a6f0e5c8b1d9a2f7e4"),
		rulebuilder.NoMatch("low entropy", "client_secret=dose00000000000000000000000000000000"),
	},
})
