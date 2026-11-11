package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "greptile-api-key",
	Confidence:  "high",
	Description: "Detected a Greptile API Key, which may expose AI-powered code search and analysis services to unauthorized access.",
	Regex:       Assignment([]string{"greptile"}, `(?i)[a-zA-Z0-9+/]{48}`),
	Keywords:    []string{"greptile"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("true positive 1", `greptile_api_key = "Bc4UcqgG6mG5ARxNAOH7TV2C/tDWaB7Kpne/pockv3iQcbSN"`, "Bc4UcqgG6mG5ARxNAOH7TV2C/tDWaB7Kpne/pockv3iQcbSN"),
		Match("true positive 2", `greptile_api_key = "cRxqPehpNKq5Rtp+QvXBPb6p6n7d+2n4a6dLZqhGQVz2w4ln"`, "cRxqPehpNKq5Rtp+QvXBPb6p6n7d+2n4a6dLZqhGQVz2w4ln"),
		Match("true positive 3", `greptile_api_key = "54tKjWAmKVvnREzrpe4d8/hfgBYf3mpcm/AeKsEHvUnWGx4g"`, "54tKjWAmKVvnREzrpe4d8/hfgBYf3mpcm/AeKsEHvUnWGx4g"),
		Match("true positive 4", "greptile = VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSY", "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSY"),
		NoMatch("Too short", `greptile_api_key = "Bc4UcqgG6mG5ARxNAOH7TV2C"`),
		NoMatch("Low entropy (all same chars)", `greptile_api_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`),
	},
})
