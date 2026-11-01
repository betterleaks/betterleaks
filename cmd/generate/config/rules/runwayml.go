package rules

import (
	"strings"

	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func RunwayMLAPIKey() *config.Rule {
	r := config.Rule{
		ID:          "runwayml-api-key",
		Confidence:  "high",
		Description: "Detected a RunwayML API key, which may allow access to Runway video, image, and audio generation and the organization's credit balance.",
		Regex:       utils.GenerateUniqueTokenRegex(`key_[0-9a-f]{128}`, false),
		Keywords:    []string{"key_"},
		// GET /v1/organization retrieves credit balance without creating a generation.
		// https://docs.dev.runwayml.com/api/#tag/Organization/paths/~1v1~1organization/get
		ValidateExpr: `let r = http.get("https://api.dev.runwayml.com/v1/organization", {
    "Authorization": "Bearer " + finding["secret"],
    "X-Runway-Version": "2024-11-06",
    "Accept": "application/json"
  }); r.status == 200 && r.json?.creditBalance != nil ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
		FilterExpr: utils.MinEntropy(3.5),
	}

	secret := "key_" + secrets.NewSecretWithEntropy(`[0-9a-f]{128}`, 3.5)
	tps := append(utils.GenerateSampleSecrets("runwayml", secret), secret, secret+";", secret+`\n`, secret+`\r`)
	fps := []string{
		secret[:len(secret)-1],       // Too short.
		secret + "a",                 // Too long.
		secret[:len(secret)-1] + "g", // Non-hexadecimal payload.
		"key_" + strings.ToUpper(secret[4:]),
		"KEY_" + secret[4:],
		"prefix_" + secret,                // Embedded in a longer identifier.
		"key_" + strings.Repeat("a", 128), // Low entropy placeholder.
	}
	return utils.Validate(r, tps, fps)
}
