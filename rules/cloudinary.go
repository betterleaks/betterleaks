package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "cloudinary-cloud-name",
	Confidence:  "high",
	Description: "Detected a Cloudinary cloud name, used as a component of the cloudinary-api-secret composite rule.",
	Regex:       `(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:CLOUD[_\s]?NAME|CLOUD)(?:.|[\n\r]){0,16}?\b([a-z0-9_-]{3,32})\b`,
	Keywords:    []string{"cloudinary"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "CLOUDINARY_CLOUD_NAME=demo", "demo"),
		rulebuilder.MatchComponent("true positive 2", "cloudinary cloud: product-images", "product-images"),
		rulebuilder.NoMatchComponent("false positive 1", "CLOUD_NAME=demo"),
		rulebuilder.NoMatchComponent("false positive 2", "CLOUDINARY_CLOUD_NAME=ab"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "cloudinary-api-key",
	Confidence:  "high",
	Description: "Detected a Cloudinary API key, used as a component of the cloudinary-api-secret composite rule.",
	Regex:       `(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:API[_\s]?KEY|KEY)(?:.|[\n\r]){0,16}?\b([0-9]{15})\b`,
	Keywords:    []string{"cloudinary"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 2.75`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "CLOUDINARY_API_KEY=123456789012345", "123456789012345"),
		rulebuilder.NoMatchComponent("false positive 1", "API_KEY=123456789012345"),
		rulebuilder.NoMatchComponent("false positive 2", "CLOUDINARY_API_KEY=12345678901234"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "cloudinary-api-secret",
	Confidence:  "high",
	Description: "Detected a Cloudinary API secret, which may allow unauthorized access to Cloudinary media and account APIs when paired with a cloud name and API key.",
	Regex:       `(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|API[_\s]?SECRET)(?:.|[\n\r]){0,32}?\b([A-Za-z0-9]{32})\b`,
	Keywords:    []string{"cloudinary"},
	Components: []config.Component{
		{RuleID: "cloudinary-api-key"},
		{RuleID: "cloudinary-cloud-name"},
	},
	ValidateExpr: `let r = http.get("https://api.cloudinary.com/v1_1/" + (components["cloudinary-cloud-name"]?.secret ?? "") + "/usage", {
    "Authorization": "Basic " + base64.encode(bytes((components["cloudinary-api-key"]?.secret ?? "") + ":" + finding["secret"])),
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "cloudinary_secret = \"aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW\"\nCLOUDINARY_API_KEY=123456789012345\nCLOUDINARY_CLOUD_NAME=demo",
			Expect: []config.ExpectedFinding{
				{Secret: "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW", ComponentSets: []map[string]string{{"cloudinary-api-key": "123456789012345", "cloudinary-cloud-name": "demo"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "API_SECRET=abcdefghijklmnopqrstuvwxyz123456"),
		rulebuilder.NoMatch("false positive 2", "CLOUDINARY_API_SECRET=abcdefghijklmnopqrstuvwxyz12345"),
	},
})
