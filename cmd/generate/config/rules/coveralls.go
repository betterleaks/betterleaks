package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
)

func CoverallsPersonalAPIToken() *config.Rule {
	r := config.Rule{
		RuleID:      "coveralls-personal-api-token",
		Description: "Detected a Coveralls personal API token, which may expose repository coverage data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"coveralls"}, `[A-Za-z0-9-]{37}`, true),
		Keywords:    []string{"coveralls"},
		Filter:      utils.MinEntropy(3.5),
	}

	tps := []string{
		`coveralls_SECRETTOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t`,
		`coveralls-SECRET-KEY=m1n2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f`,
		`coveralls_PRIVATEKEY=1234567890bcdefghijklmnpqrstuvwxyza12`,
	}
	return utils.Validate(r, tps, nil)
}
