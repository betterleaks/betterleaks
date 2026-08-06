package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func SegmentPublicAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "segment-public-api-token.1",
		Description: "Segment workspace bearer token for the Public API.",
		Regex:       utils.GenerateUniqueTokenRegex(`sgp_[A-Za-z0-9]{64}`, false),
		Keywords:    []string{"sgp_"},
		ValidateExpr: `let r = http.get("https://api.segmentapis.com/", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "invalid",
    "reason": "Not authorized"
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.3),
	}

	// validate
	tps := []string{
		"SEGMENT_PUBLIC_API_TOKEN=sgp_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("64"), 3.3),
	}
	fps := []string{
		`SEGMENT_PUBLIC_API_TOKEN=sgp_short`,
		`SOURCEGRAPH_TOKEN=sgp_210f1131b08e93adcfc3f05faa2d768ff883a61f`,
	}
	return utils.Validate(r, tps, fps)
}
