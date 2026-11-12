package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "exoscale-api-key",
	Confidence:  "high",
	Description: "Identified an Exoscale API key paired with a secret, which together grant programmatic access to Exoscale cloud resources.",
	Regex:       rulebuilder.Token(`EXO[a-zA-Z0-9]{24,30}`),
	Keywords:    []string{"exo"},
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Components: []config.Component{
		{
			RuleID: "exoscale-api-secret",
			Within: "5L",
		},
	},
	ValidateExpr: `let ts = time.nowUnix(); (let sig = crypto.hmacSha256(
      bytes((components["exoscale-api-secret"]?.secret ?? "")),
      bytes("GET /v2/zone\n\n\n\n" + ts)
    ); (let r = http.get("https://api-ch-gva-2.exoscale.com/v2/zone", {
        "Authorization": "EXO2-HMAC-SHA256 credential=" + finding["secret"] + ",expires=" + ts + ",signature=" + base64.encode(sig)
      }); r.status == 200 ? {
        "result": "valid"
      } : r.status in [401, 403] ? {
        "result": "invalid",
        "reason": "Unauthorized"
      } : validate.unknown(r)))`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "exoscale_api_key = \"EXO1f7b169c846f218ab552fa82\"\nexoscaleToken = \"WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH\"",
			Expect: []config.ExpectedFinding{
				{Secret: "EXO1f7b169c846f218ab552fa82", ComponentSets: []map[string]string{{"exoscale-api-secret": "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"}}},
			},
		},
		rulebuilder.NoMatch("Too short", `exoscale_api_key = "EXOabc123"`),
		rulebuilder.NoMatch("Wrong prefix", `exoscale_api_key = "EXAabc123def456ghi789jkl012mno345"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "exoscale-api-secret",
	Confidence:  "high",
	Description: "Identified an Exoscale API secret, used as a component of the exoscale-api-key composite rule.",
	Regex:       rulebuilder.Assignment([]string{"exoscale"}, `(?i)[A-Za-z0-9_\-]{40,60}`),
	Keywords:    []string{"exoscale"},
	FilterExpr:  rulebuilder.MinEntropy(4.0),
	SkipReport:  true,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("assignment", `exoscaleToken = "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"`, "WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxH"),
	},
})
