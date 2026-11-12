package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

const highnoteLiveValidationExpr = `let r = http.post("https://api.us.highnote.com/graphql", {
    "Authorization": "Basic " + base64.encode(bytes(finding["secret"])),
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"query\":\"query { ping }\"}"); r.status == 200 && (r.json?.data?.ping ?? "") == "pong" ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

var _ = rulebuilder.Add(config.Rule{
	ID:          "highnote-secret-live-key",
	Confidence:  "high",
	Description: "Highnote secret API key for the live environment.",
	Regex: rulebuilder.Assignment(
		[]string{`highnote(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token|sk[_. -]*live)`},
		`sk_live_a2V5Xz[A-Za-z0-9+/]{69}={0,2}`,
	),
	Keywords:     []string{"highnote"},
	ValidateExpr: highnoteLiveValidationExpr,
	FilterExpr:   rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", `HIGHNOTE_SK_LIVE="sk_live_a2V5XzVD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0T"`, "sk_live_a2V5XzVD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0T"),
		rulebuilder.NoMatch("false positive 1", `HIGHNOTE_SK_LIVE="sk_live_short"`),
		rulebuilder.NoMatch("false positive 2", `WORKOS_API_KEY="sk_live_a2V5XzAxS1BSWE1LTjBEWE1INlpBU0VEWjU2VFE3LFdjOWxFMTNDS29xRkdlYU9uMUpDbUpTZWE"`),
	},
})
