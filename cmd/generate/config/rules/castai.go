package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CastAI() *config.Rule {
	// Cast AI operates regional API endpoints (US, EU, India). An API key is
	// scoped to the region it was created in, so all three hosts are tried
	// before a key is rejected. The /v1/me endpoint returns the current user's
	// profile, including the email associated with the account.
	r := config.Rule{
		RuleID:      "castai-api-key",
		Description: "Identified a pattern that may indicate a Cast AI API key.",
		Regex:       regexp.MustCompile(`\b(castai_v1_[a-z0-9]{64}_[a-z0-9]{8})\b`),
		Entropy:     3,
		Keywords: []string{
			"castai_v1_", // Prefix
		},
		ValidateExpr: `let us = http.get("https://api.cast.ai/v1/me", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); us.status == 200 && (us.body contains "\"email\"") ? {
    "result": "valid",
    "email": (us.json?.email ?? "")
  } : (let eu = http.get("https://api.eu.cast.ai/v1/me", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); eu.status == 200 && (eu.body contains "\"email\"") ? {
    "result": "valid",
    "email": (eu.json?.email ?? "")
  } : (let india = http.get("https://api.india.cast.ai/v1/me", {
    "X-API-Key": finding["secret"],
    "Accept": "application/json"
  }); india.status == 200 && (india.body contains "\"email\"") ? {
    "result": "valid",
    "email": (india.json?.email ?? "")
  } : us.status in [401, 403] && eu.status in [401, 403] && india.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(india)))`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("CastAI", "castai_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_aabb92b5")
	tps = append(tps, utils.GenerateSampleSecrets("CastAI", "castai_v1_"+secrets.NewSecret("[a-z0-9]{64}_[a-z0-9]{8}"))...)
	fps := []string{
		`key = test_v1_2cb5a70064f60ba2f5507bcbb02938a5a0483bf2a9742d08c5c274c827c9f6ea_037192b5`,
		`key = cast_v1_2cb5a70064f60ba2f5507bcxxxx`,
	}
	return utils.Validate(r, tps, fps)

}
