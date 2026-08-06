package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func PostHogProjectAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "posthog-project-api-key",
		Description: "Detected a PostHog Project API Key, a public write-only token used to send events to a PostHog project.",
		// "phc_" + a random token. The encoding has changed over time, so the body
		// length varies across keys still in the wild:
		//   - base62(32 bytes)          → 41-43 chars (2021 .. early 2026)
		//   - base57(32 bytes), top-bit → exactly 44 chars (current, since #52495)
		Regex:    utils.GenerateUniqueTokenRegex(`phc_[a-zA-Z0-9_\-]{41,44}`, true),
		Keywords: []string{"phc_"},
		Filter:   `entropy(finding["secret"]) <= 3.0`,
	}

	// Positives are generated at scan time (never committed) so no realistic-looking
	// key lands in source, where secret scanners would flag it. One per historical
	// body length so the {41,44} range can't silently regress.
	tps := utils.GenerateSampleSecrets("posthog", "phc_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{44}`, 3.0))
	tps = append(tps,
		"phc_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{41}`, 3.0), // base62(32B) short tail
		"phc_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{43}`, 3.0), // base62(32B) era
	)
	fps := []string{
		// Out of the {41,44} range — generated so nothing key-shaped is committed.
		"phc_" + secrets.NewSecret(`[a-zA-Z0-9]{40}`), // too short
		"phc_" + secrets.NewSecret(`[a-zA-Z0-9]{45}`), // too long
		// Wrong prefix
		`phd_E123456789012345678901234567890123456789012`,
	}
	return utils.Validate(r, tps, fps)
}

func PostHogPersonalAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "posthog-personal-api-key",
		Description: "Detected a PostHog Personal API Key, which may expose administrative access to PostHog analytics projects.",
		// "phx_" + a random token. The encoding has changed over time, so the body
		// length varies across keys still in the wild:
		//   - base62(32 bytes)          → 41-43 chars (2021 .. 2024, before #22362)
		//   - base62(35 bytes)          → 45-48 chars (2024 .. early 2026, mostly 47)
		//   - base57(35 bytes), top-bit → 48-49 chars (current, since #52495)
		Regex:    utils.GenerateUniqueTokenRegex(`phx_[a-zA-Z0-9_\-]{41,49}`, true),
		Keywords: []string{"phx_"},
		Filter:   `entropy(finding["secret"]) <= 3.0`,
		// A valid key hits us/eu.posthog.com and returns 200 (has user:read) or
		// 403 (authenticated but missing the user:read scope); a revoked/unknown
		// key returns 401. Keys are region-bound, so any non-valid US response
		// (401, or a 429/5xx outage) falls back to EU. Only report "invalid" when
		// both regions definitively return 401 — if either errored, stay unknown.
		ValidateExpr: `let us = http.get("https://us.posthog.com/api/users/@me/", {
    "Authorization": "Bearer " + finding["secret"]
  }); us.status in [200, 403] ? {
    "result": "valid",
    "region": "us",
    "email": (us.json?.email ?? ""),
    "organization": (us.json?.organization?.name ?? "")
  } : (let eu = http.get("https://eu.posthog.com/api/users/@me/", {
    "Authorization": "Bearer " + finding["secret"]
  }); eu.status in [200, 403] ? {
    "result": "valid",
    "region": "eu",
    "email": (eu.json?.email ?? ""),
    "organization": (eu.json?.organization?.name ?? "")
  } : (us.status == 401 && eu.status == 401) ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(eu))`,
	}

	// Positives are generated at scan time (never committed) so no realistic-looking
	// key lands in source, where secret scanners would flag it. One per historical
	// body length so the {41,49} range can't silently regress.
	tps := utils.GenerateSampleSecrets("posthog", "phx_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{49}`, 3.0))
	tps = append(tps,
		"phx_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{41}`, 3.0), // base62(32B) short tail
		"phx_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{43}`, 3.0), // base62(32B) era
		"phx_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{47}`, 3.0), // base62(35B) era (most common)
		"phx_"+secrets.NewSecretWithEntropy(`[a-zA-Z0-9_\-]{48}`, 3.0), // base57(35B) era
	)
	fps := []string{
		// Out of the {41,49} range — generated so nothing key-shaped is committed.
		"phx_" + secrets.NewSecret(`[a-zA-Z0-9]{40}`), // too short
		"phx_" + secrets.NewSecret(`[a-zA-Z0-9]{50}`), // too long
		// Wrong prefix
		`phy_FNKCx83Ko0JQMuZH1zz94xgK798TCUybkf79ZKYKwKQWbEw`,
	}
	return utils.Validate(r, tps, fps)
}
