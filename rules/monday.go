package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "monday-api-token.1",
	Confidence:  "high",
	Specificity: 10,
	Description: "monday.com API token, which may grant the same workspace access as its associated user or application.",
	Regex: rulebuilder.Assignment(
		[]string{"monday"},
		`eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{50,1000}\.[A-Za-z0-9_-]{20,500}`,
	),
	Keywords: []string{"monday"},
	ValidateExpr: `let r = http.post("https://api.monday.com/v2", {
    "Authorization": finding["secret"],
    "Content-Type": "application/json",
    "Accept": "application/json"
  }, "{\"query\":\"query { me { id name } }\"}"); r.status == 200
    && (r.body contains "\"data\"") && (r.body contains "\"me\"")
    && (r.body contains "\"id\"") ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.5),
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "MONDAY_API_TOKEN=eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH.eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH.eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		rulebuilder.Match("true positive 2", `monday access token: "eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH.eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"`, "eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH.eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		rulebuilder.NoMatch("false positive 1", "API_TOKEN=eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH.eyJWE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZzOK8pMcG7ubf2TxReZd1UXAceqba86woUt0S8fdI2myN1nZ6NYCy0bQx6umpyk9dz5c02tMq.WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		rulebuilder.NoMatch("false positive 2", "MONDAY_API_TOKEN=eyJshort.eyJshort.short"),
	},
})
