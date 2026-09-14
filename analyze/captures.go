package analyze

import "github.com/betterleaks/betterleaks/v2/config"

// RequiredCaptures returns statically required primary capture names. Use
// Analyzer.Requirements for the complete primary and component input contract.
func RequiredCaptures(rule config.Rule, expressions ...string) []string {
	if len(expressions) == 0 {
		expressions = []string{rule.ValidateExpr}
	}
	return requiredNames(captureReferences(expressions...)[""], primaryCapture(rule))
}
