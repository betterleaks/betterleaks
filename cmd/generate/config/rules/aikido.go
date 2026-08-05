package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AikidoClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "aikido-client-id",
		Description: "Detected an Aikido client ID, used as a component of the aikido-client-secret composite rule.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIK_CLIENT_[A-Za-z0-9]{24}`, false),
		Keywords:    []string{"AIK_CLIENT_"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`AIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1L2`,
	}
	fps := []string{
		`AIK_CLIENT_ID=AIK_CLIENT_a1B2c3D4e5F6g7H8i9J0k1`,
	}
	return utils.Validate(r, tps, fps)
}

func AikidoClientSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "aikido-client-secret",
		Description: "Detected an Aikido client secret, which may allow unauthorized access to Aikido APIs when paired with a client ID.",
		Regex:       utils.GenerateUniqueTokenRegex(`AIK_SECRET_[A-Za-z0-9]{64}`, false),
		Keywords:    []string{"AIK_SECRET_"},
		Components: []*config.Component{
			{RuleID: "aikido-client-id"},
		},
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`AIK_CLIENT_SECRET=AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2`,
	}
	fps := []string{
		`AIK_CLIENT_SECRET=AIK_SECRET_a1B2c3D4e5F6g7H8i9J0k1L2`,
	}
	return utils.Validate(r, tps, fps)
}

func AikidoCIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "aikido-ci-token",
		Description: "Detected an Aikido CI token, which may allow unauthorized CI scan integration activity in Aikido.",
		Regex:       regexp.MustCompile(`\b(AIK_CI_[A-Za-z0-9]{20,44})\b`),
		Keywords:    []string{"AIK_CI_"},
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`AIKIDO_TOKEN=AIK_CI_a1B2c3D4e5F6g7H8i9J0k1L2`,
	}
	fps := []string{
		`AIKIDO_TOKEN=AIK_CI_short`,
	}
	return utils.Validate(r, tps, fps)
}
