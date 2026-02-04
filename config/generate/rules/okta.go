package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func OktaAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "okta-access-token",
		Description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
		Regex:       utils2.GenerateSemiGenericRegex([]string{`(?-i:[Oo]kta|OKTA)`}, `00[\w=\-]{40}`, false),
		Entropy:     4,
		Keywords: []string{
			"okta",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("okta", secrets.NewSecret(`00[\w=\-]{40}`))
	tps = append(tps,
		`"oktaApiToken": "00ebObu4zSNkyc6dimLvUwq4KpTEop-PCEnnfSTpD3",`,       // gitleaks:allow
		`			var OktaApiToken = "00fWkOjwwL9xiFd-Vfgm_ePATIRxVj852Iblbb1DS_";`, // gitleaks:allow
	)
	fps := []string{
		`oktaKey = 00000000000000000000000000000000000TUVWXYZ`,   // low entropy
		`rookTable = 0023452Lllk2KqjLBvaxANWEgTd7bqjsxjo8aZj0wd`, // wrong case
	}
	return utils2.Validate(r, tps, fps)
}

// TODO: Okta client secret?
