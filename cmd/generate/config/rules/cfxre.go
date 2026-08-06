package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CfxreServerKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cfxre-server-key",
		Description: "Cfx.re FiveM server key.",
		Regex:       regexp.MustCompile(`\b(cfxk_[a-zA-Z0-9_-]{20,100})`),
		Keywords:    []string{"cfxk_"},
		Filter:      `entropy(finding["secret"]) <= 3.5`,
	}

	// validate
	tps := []string{
		`sv_licenseKey "cfxk_AbCdEfGhIjKlMnOpQrStUvWx"`,
	}
	fps := []string{
		`cfxk_short`,
	}
	return utils.Validate(r, tps, fps)
}
