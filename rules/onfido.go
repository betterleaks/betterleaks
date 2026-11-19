package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(onfidoLiveAPIToken("onfido-live-api-token-eu",
	`api_live\.[A-Za-z0-9_-]{20,80}`,
	"api_live.",
	"https://api.eu.onfido.com/v3.6/webhooks/",
	rulebuilder.Match("true positive 1", "ONFIDO_API_TOKEN=api_live.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps", "api_live.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"),
	rulebuilder.NoMatch("false positive 1", "ONFIDO_API_TOKEN=api_live.short"),
	rulebuilder.NoMatch("false positive 2", "ONFIDO_API_TOKEN=api_live.00000000000000000000000000000000"),
))

var _ = rulebuilder.Add(onfidoLiveAPIToken("onfido-live-api-token-us",
	`api_live_us\.[A-Za-z0-9_-]{20,80}`,
	"api_live_us.",
	"https://api.us.onfido.com/v3.6/webhooks/",
	rulebuilder.Match("true positive 1", "ONFIDO_API_TOKEN=api_live_us.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps", "api_live_us.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"),
	rulebuilder.NoMatch("false positive 1", "ONFIDO_API_TOKEN=api_live_us.short"),
	rulebuilder.NoMatch("false positive 2", "ONFIDO_API_TOKEN=api_live_us.00000000000000000000000000000000"),
))

var _ = rulebuilder.Add(onfidoLiveAPIToken("onfido-live-api-token-ca",
	`api_live_ca\.[A-Za-z0-9_-]{20,80}`,
	"api_live_ca.",
	"https://api.ca.onfido.com/v3.6/webhooks/",
	rulebuilder.Match("true positive 1", "ONFIDO_API_TOKEN=api_live_ca.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps", "api_live_ca.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrps"),
	rulebuilder.NoMatch("false positive 1", "ONFIDO_API_TOKEN=api_live_ca.short"),
	rulebuilder.NoMatch("false positive 2", "ONFIDO_API_TOKEN=api_live_ca.00000000000000000000000000000000"),
))

func onfidoLiveAPIToken(ruleID, tokenRegex, keyword, endpoint string, tests ...config.RuleTest) config.Rule {
	return config.Rule{
		ID:          ruleID,
		Confidence:  "high",
		Description: "Onfido live API token.",
		Regex:       rulebuilder.Token(tokenRegex),
		Keywords:    []string{keyword},
		ValidateExpr: `let r = http.get("` + endpoint + `", {
    "Authorization": "Token token=" + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: rulebuilder.MinEntropy(3.5),
		Tests:      tests,
	}
}
