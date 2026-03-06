package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func PyPiUploadToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
		RuleID:      "pypi-upload-token",
		Regex:       regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`),
		Entropy:     3,
		Keywords: []string{
			"pypi-AgEIcHlwaS5vcmc",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("pypi", "pypi-AgEIcHlwaS5vcmc"+secrets.NewSecretWithEntropy(utils.Hex("32"), 3)+secrets.NewSecretWithEntropy(utils.Hex("32"), 3))
	return utils.Validate(r, tps, nil)
}
