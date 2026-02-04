package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
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
	tps := utils2.GenerateSampleSecrets("pypi", "pypi-AgEIcHlwaS5vcmc"+secrets.NewSecret(utils2.Hex("32"))+secrets.NewSecret(utils2.Hex("32")))
	return utils2.Validate(r, tps, nil)
}
