package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CloudinaryCloudName() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudinary-cloud-name",
		Description: "Detected a Cloudinary cloud name, used as a component of the cloudinary-api-secret composite rule.",
		Regex:       regexp.MustCompile(`(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:CLOUD[_\s]?NAME|CLOUD)(?:.|[\n\r]){0,16}?\b([a-z0-9_-]{3,32})\b`),
		Keywords:    []string{"cloudinary"},
		SkipReport:  true,
	}

	tps := []string{
		`CLOUDINARY_CLOUD_NAME=demo`,
		`cloudinary cloud: product-images`,
	}
	fps := []string{
		`CLOUD_NAME=demo`,
		`CLOUDINARY_CLOUD_NAME=ab`,
	}
	return utils.Validate(r, tps, fps)
}

func CloudinaryAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudinary-api-key",
		Description: "Detected a Cloudinary API key, used as a component of the cloudinary-api-secret composite rule.",
		Regex:       regexp.MustCompile(`(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:API[_\s]?KEY|KEY)(?:.|[\n\r]){0,16}?\b([0-9]{15})\b`),
		Keywords:    []string{"cloudinary"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`CLOUDINARY_API_KEY=123456789012345`,
	}
	fps := []string{
		`API_KEY=123456789012345`,
		`CLOUDINARY_API_KEY=12345678901234`,
	}
	return utils.Validate(r, tps, fps)
}

func CloudinaryAPISecret() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudinary-api-secret",
		Description: "Detected a Cloudinary API secret, which may allow unauthorized access to Cloudinary media and account APIs when paired with a cloud name and API key.",
		Regex:       regexp.MustCompile(`(?i)\bcloudinary(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|API[_\s]?SECRET)(?:.|[\n\r]){0,32}?\b([A-Za-z0-9]{32})\b`),
		Keywords:    []string{"cloudinary"},
		RequiredRules: []*config.Required{
			{RuleID: "cloudinary-api-key"},
			{RuleID: "cloudinary-cloud-name"},
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.cloudinary.com/v1_1/" + captures["cloudinary-cloud-name"] + "/usage", {
    "Authorization": "Basic " + base64.encode(bytes(captures["cloudinary-api-key"] + ":" + finding["secret"])),
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`cloudinary_secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW"`,
	}
	fps := []string{
		`API_SECRET=abcdefghijklmnopqrstuvwxyz123456`,
		`CLOUDINARY_API_SECRET=abcdefghijklmnopqrstuvwxyz12345`,
	}
	return utils.Validate(r, tps, fps)
}
