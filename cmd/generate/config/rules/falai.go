package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FalAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "fal-api-key.1",
		Confidence:  "high",
		Description: "Fal.ai API key, which may allow access to model execution, billing, and platform APIs.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{"falai", "fal_ai", "fal-ai", "fal.ai", "fal-api", "fal_api", "fal_key", "fal-key"},
			utils.Hex("8")+`-`+utils.Hex("4")+`-`+utils.Hex("4")+`-`+utils.Hex("4")+`-`+utils.Hex("12")+`:`+utils.Hex("32"),
			false,
		),
		Keywords: []string{"falai", "fal_ai", "fal-ai", "fal.ai", "fal-api", "fal_api", "fal_key", "fal-key"},
		ValidateExpr: `let r = http.get("https://api.fal.ai/v1/models/pricing?endpoint_id=fal-ai%2Fflux%2Fdev", {
    "Authorization": "Key " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"prices\"") ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.error?.type ?? "") == "authorization_error" ? {
    "result": "invalid",
    "reason": (r.json?.error?.message ?? "Invalid API key")
  } : validate.unknown(r)`,
		Filter: utils.MinEntropy(3.5),
	}

	key := secrets.NewSecretWithEntropy(`[a-f0-9]{8}`, 2.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{4}`, 1.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{4}`, 1.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{4}`, 1.5) + "-" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{12}`, 2.5) + ":" +
		secrets.NewSecretWithEntropy(`[a-f0-9]{32}`, 3.5)
	tps := []string{
		`fal.ai api key: "` + key + `"`,
		`fal-api=` + key,
	}
	fps := []string{
		`API_KEY=` + key,
		`FAL_KEY=847c02a9-db27-42d5-b781-9cf5c72b3e0d:short`,
		`FAL_KEY=00000000-0000-0000-0000-000000000000:00000000000000000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}
