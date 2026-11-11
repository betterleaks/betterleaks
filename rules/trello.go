package rules

import "github.com/betterleaks/betterleaks/v2/config"

// TrelloAccessToken has never been registered in the default config.
func TrelloAccessToken() config.Rule {
	return config.Rule{
		ID:          "trello-access-token",
		Confidence:  "high",
		Description: "Trello Access Token",
		Regex:       Assignment([]string{"trello"}, `(?i)[a-zA-Z-0-9]{32}`),

		Keywords: []string{
			"trello",
		},
		Tests: []config.RuleTest{
			Match("trello assignment", `trelloToken = "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"`, "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"),
		},
	}
}
