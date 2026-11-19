package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// CfxreServerKey is not registered in the default config: it was found in
// GHAS, but is not worth adding at this time.
func CfxreServerKey() config.Rule {
	return config.Rule{
		ID:          "cfxre-server-key",
		Confidence:  "high",
		Description: "Cfx.re FiveM server key.",
		Regex:       `\b(cfxk_[a-zA-Z0-9_-]{20,100})`,
		Keywords:    []string{"cfxk_"},
		FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
		Tests: []config.RuleTest{
			rulebuilder.Match("true positive 1", `sv_licenseKey "cfxk_AbCdEfGhIjKlMnOpQrStUvWx"`, "cfxk_AbCdEfGhIjKlMnOpQrStUvWx"),
			rulebuilder.NoMatch("false positive 1", "cfxk_short"),
		},
	}
}
