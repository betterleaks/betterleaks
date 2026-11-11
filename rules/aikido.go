package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "aikido-client-id",
	Confidence:  "high",
	Description: "Detected an Aikido client ID, used as a component of the aikido-client-secret composite rule.",
	Regex:       Token(`AIK_CLIENT_[A-Za-z0-9]{24}`),
	Keywords:    []string{"AIK_CLIENT_"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "AIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1L2",
			Expect: []config.ExpectedFinding{
				{Secret: "AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1L2"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "AIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "aikido-client-secret",
	Confidence:  "high",
	Description: "Detected an Aikido client secret, which may allow unauthorized access to Aikido APIs when paired with a client ID.",
	Regex:       Token(`AIK_SECRET_[A-Za-z0-9]{64}`),
	Keywords:    []string{"AIK_SECRET_"},
	Components: []config.Component{
		{RuleID: "aikido-client-id"},
	},
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "AIK_CLIENT_SECRET=AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2\nAIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1L2",
			Expect: []config.ExpectedFinding{
				{Secret: "AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2", ComponentSets: []map[string]string{{"aikido-client-id": "AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1L2"}}},
			},
		},
		NoMatch("false positive 1", "AIK_CLIENT_SECRET=AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2"),
	},
})

var _ = Add(config.Rule{
	ID:          "aikido-ci-token",
	Confidence:  "high",
	Description: "Detected an Aikido CI token, which may allow unauthorized CI scan integration activity in Aikido.",
	Regex:       `\b(AIK_CI_[A-Za-z0-9]{20,44})\b`,
	Keywords:    []string{"AIK_CI_"},
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		Match("true positive 1", "AIKIDO_TOKEN=AIK_CI_a1B2c3D4e5F6g7H8i9J0k1L2", "AIK_CI_a1B2c3D4e5F6g7H8i9J0k1L2"),
		NoMatch("false positive 1", "AIKIDO_TOKEN=AIK_CI_short"),
	},
})
