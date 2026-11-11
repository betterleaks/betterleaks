package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "elevenlabs-api-key",
	Confidence:  "high",
	Description: "Detected an ElevenLabs API Key, which may expose AI voice synthesis services to unauthorized access.",
	Regex:       Assignment([]string{"elevenlabs"}, `(?i)sk_[0-9a-f]{48}`),
	Keywords:    []string{"elevenlabs"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("elevenlabs assignment", `elevenlabsToken = "sk_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4"`, "sk_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4"),
		NoMatch("Too short", "elevenlabs_key = sk_2a30e5a0d39d5f2c5f6a9d2f95cd0160"),
		NoMatch("Wrong prefix", "elevenlabs_key = ak_2a30e5a0d39d5f2c5f6a9d2f95cd016049a6323985479bfd"),
	},
})
