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
		rulebuilder.MatchComponent("production client ID", "EBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab", "MyApp-MyApp-PRD-1a2b3c4d-567890ab"),
		rulebuilder.NoMatchComponent("sandbox client ID", "EBAY_CLIENT_ID=MyApp-MyApp-SBX-1a2b3c4d-567890ab"),
		rulebuilder.NoMatch("hidden when scanned alone", "EBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab"),
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
let secret = finding["secret"];
let url = "https://api.ebay.com/identity/v1/oauth2/token";
let payload = "grant_type=refresh_token&refresh_token=betterleaks-validation-token";
let r = http.post(url, {
  "Authorization": "Basic " + base64.encode(bytes(clientID + ":" + secret)),
  "Content-Type": "application/x-www-form-urlencoded",
  "Accept": "application/json"
}, payload);
let isJSON = lower(trim(split(r.headers["content-type"] ?? "", ";")[0])) == "application/json";
let body = type(r.json) == "map" ? r.json : {};
r.status == 401 && isJSON && (body?.error ?? "") == "invalid_client" ? {
  "result": "invalid",
  "reason": "Invalid client"
} : r.status == 400 && isJSON && (body?.error ?? "") == "invalid_grant" ? (
  let altered = secret[:len(secret)-1] + (secret[len(secret)-1:] == "0" ? "1" : "0");
  let control = http.post(url, {
    "Authorization": "Basic " + base64.encode(bytes(clientID + ":" + altered)),
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  }, payload);
  let controlBody = type(control.json) == "map" ? control.json : {};
  control.status == 401 && lower(trim(split(control.headers["content-type"] ?? "", ";")[0])) == "application/json" &&
    (controlBody?.error ?? "") == "invalid_client" ? {
    "result": "valid"
  } : {
    "result": "unknown",
    "reason": "Refresh-token rejection did not establish client authentication"
  }
) : validate.unknown(r)`,
	FilterExpr: rulebuilder.MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "secret with client ID",
			Input: "EBAY_CLIENT_SECRET=PRD-1f7b169c-1f7b-1f7b-1f7b-1f7b169c\nEBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab",
			Expect: []config.ExpectedFinding{
				{Secret: "PRD-1f7b169c-1f7b-1f7b-1f7b-1f7b169c", ComponentSets: []map[string]string{{"ebay-client-id": "MyApp-MyApp-PRD-1a2b3c4d-567890ab"}}},
			},
		},
		rulebuilder.NoMatch("secret without client ID", "EBAY_CLIENT_SECRET=PRD-1f7b169c-1f7b-1f7b-1f7b-1f7b169c"),
		rulebuilder.NoMatch("sandbox secret", "EBAY_CLIENT_SECRET=SBX-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b\nEBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab"),
	},
})
