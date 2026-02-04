package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func PulumiAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pulumi-api-token",
		Description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
		Regex:       utils2.GenerateUniqueTokenRegex(`pul-[a-f0-9]{40}`, false),
		Entropy:     2,
		Keywords: []string{
			"pul-",
		},
	}

	// validate
	tps := utils2.GenerateSampleSecrets("pulumi-api-token", "pul-"+secrets.NewSecret(utils2.Hex("40")))
	fps := []string{
		`                        <img src="./assets/vipul-f0eb1acf0da84c06a50c5b2c59932001997786b176dec02bd16128ee9ea83628.png" alt="" class="w-16 h-16 rounded-full">`,
	}
	return utils2.Validate(r, tps, fps)
}
