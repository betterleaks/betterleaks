package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func EBayClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "ebay-client-secret",
		Description: "eBay client secret.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`ebay(?:[_. -]*(?:client|api))?[_. -]*(?:secret|key)`},
			`(?:PRD|SBX)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4,12}`,
			false,
		),
		Keywords: []string{"ebay"},
		Filter:   utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"EBAY_CLIENT_SECRET=PRD-" + secrets.NewSecret(utils.Hex("8")) + "-" + secrets.NewSecret(utils.Hex("4")) + "-" + secrets.NewSecret(utils.Hex("4")) + "-" + secrets.NewSecret(utils.Hex("4")) + "-" + secrets.NewSecret(utils.Hex("8")),
	}
	fps := []string{
		`EBAY_CLIENT_SECRET=PRD-short`,
	}
	return utils.Validate(r, tps, fps)
}
