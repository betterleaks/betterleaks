package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "segment-public-api-token.1",
	Confidence:  "high",
	Description: "Segment workspace bearer token for the Public API.",
	Regex:       Token(`sgp_[A-Za-z0-9]{64}`),
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
	FilterExpr: MinEntropy(3.3),
	Tests: []config.RuleTest{
		Match("true positive 1", "SEGMENT_PUBLIC_API_TOKEN=sgp_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc", "sgp_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lc"),
		NoMatch("false positive 1", "SEGMENT_PUBLIC_API_TOKEN=sgp_short"),
		NoMatch("false positive 2", "SOURCEGRAPH_TOKEN=sgp_210f1131b08e93adcfc3f05faa2d768ff883a61f"),
	},
})
