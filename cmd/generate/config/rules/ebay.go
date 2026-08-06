package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func EBayClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "ebay-client-id",
		Description: "eBay client ID, used as a component of the eBay client-secret composite rule.",
		Regex:       regexp.MustCompile(`\b([a-zA-Z0-9_-]+-[a-zA-Z0-9_-]+-PRD-[a-f0-9]{8,12}-[a-f0-9]{8,12})`),
		Keywords:    []string{"-PRD-"},
		SkipReport:  true,
		Filter:      utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		`EBAY_CLIENT_ID=MyApp-MyApp-PRD-1a2b3c4d-567890ab`,
	}
	fps := []string{
		`EBAY_CLIENT_ID=MyApp-MyApp-SBX-1a2b3c4d-567890ab`,
	}
	return utils.Validate(r, tps, fps)
}

func EBayClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "ebay-client-secret",
		Description: "eBay client secret.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`ebay(?:[_. -]*(?:client|api))?[_. -]*(?:secret|key)`},
			`PRD-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4,12}`,
			false,
		),
		Keywords: []string{"ebay"},
		RequiredRules: []*config.Required{
			{RuleID: "ebay-client-id"},
		},
		ValidateExpr: `let clientID = captures["ebay-client-id"];
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
		Filter: utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		"EBAY_CLIENT_SECRET=PRD-" + secrets.NewSecret(utils.Hex("8")) + "-" + secrets.NewSecret(utils.Hex("4")) + "-" + secrets.NewSecret(utils.Hex("4")) + "-" + secrets.NewSecret(utils.Hex("4")) + "-" + secrets.NewSecret(utils.Hex("8")),
	}
	fps := []string{
		`EBAY_CLIENT_SECRET=SBX-1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b`,
	}
	return utils.Validate(r, tps, fps)
}
