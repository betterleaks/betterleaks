package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "ebay-client-id",
	Confidence:  "high",
	Description: "eBay client ID, used as a component of the eBay client-secret composite rule.",
	Regex:       `\b([a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+-PRD-[a-f0-9]{8,12}-[a-f0-9]{8,12})`,
	Keywords:    []string{"-prd-"},
	SkipReport:  true,
	FilterExpr:  rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "EBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab", "MyApp-MyApp-PRD-1a2b3c4d-567890ab"),
		rulebuilder.NoMatchComponent("false positive 1", "EBAY_CLIENT_ID=MyApp-MyApp-SBX-1a2b3c4d-567890ab"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "ebay-client-secret",
	Confidence:  "high",
	Description: "eBay client secret.",
	Regex: rulebuilder.Assignment(
		[]string{`ebay(?:[_. -]*(?:client|api))?[_. -]*(?:secret|key)`},
		`PRD-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4,12}`,
	),
	Keywords: []string{"ebay"},
	Components: []config.Component{
		{RuleID: "ebay-client-id"},
	},
	ValidateExpr: `let clientID = (components["ebay-client-id"]?.secret ?? "");
let r = http.post("https://api.ebay.com/identity/v1/oauth2/token/introspect", {
  "Authorization": "Basic " + base64.encode(bytes(clientID + ":" + finding["secret"])),
  "Content-Type": "application/x-www-form-urlencoded",
  "Accept": "application/json"
}, "token=betterleaks-validation-token&token_type_hint=access_token");
r.status == 200 && (r.json?.active ?? true) == false ? {
  "result": "valid"
} : r.status == 401 && (r.json?.error ?? "") == "invalid_client" ? {
  "result": "invalid",
  "reason": "Invalid client"
} : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "EBAY_CLIENT_SECRET=PRD-1f7b169c-1f7b-1f7b-1f7b-1f7b169c\nEBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab",
			Expect: []config.ExpectedFinding{
				{Secret: "PRD-1f7b169c-1f7b-1f7b-1f7b-1f7b169c", ComponentSets: []map[string]string{{"ebay-client-id": "MyApp-MyApp-PRD-1a2b3c4d-567890ab"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "EBAY_CLIENT_SECRET=SBX-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b"),
	},
})
