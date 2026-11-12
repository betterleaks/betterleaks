package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "posthog-project-api-key",
	Confidence:  "high",
	Description: "Detected a PostHog Project API Key, a public write-only token used to send events to a PostHog project.",
	// "phc_" + a random token. The encoding has changed over time, so the body
	// length varies across keys still in the wild:
	//   - base62(32 bytes)          → 41-43 chars (2021 .. early 2026)
	//   - base57(32 bytes), top-bit → exactly 44 chars (current, since #52495)
	Regex:      rulebuilder.Token(`(?i)phc_[a-zA-Z0-9_\-]{41,44}`),
	Keywords:   []string{"phc_"},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `posthogToken = "phc_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92"`, "phc_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92"),
		rulebuilder.Match("bare secret", "phc_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHC", "phc_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHC"),
		rulebuilder.Match("bare secret 2", "phc_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "phc_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		rulebuilder.NoMatch("too short", "phc_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.NoMatch("too long", "phc_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9"),
		rulebuilder.NoMatch("Wrong prefix", "phd_E123456789012345678901234567890123456789012"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "posthog-personal-api-key",
	Confidence:  "high",
	Description: "Detected a PostHog Personal API Key, which may expose administrative access to PostHog analytics projects.",
	// "phx_" + a random token. The encoding has changed over time, so the body
	// length varies across keys still in the wild:
	//   - base62(32 bytes)          → 41-43 chars (2021 .. 2024, before #22362)
	//   - base62(35 bytes)          → 45-48 chars (2024 .. early 2026, mostly 47)
	//   - base57(35 bytes), top-bit → 48-49 chars (current, since #52495)
	Regex:      rulebuilder.Token(`(?i)phx_[a-zA-Z0-9_\-]{41,49}`),
	Keywords:   []string{"phx_"},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	// A valid key hits us/eu.posthog.com and returns 200 (has user:read) or
	// 403 (authenticated but missing the user:read scope); a revoked/unknown
	// key returns 401. Keys are region-bound, so any non-valid US response
	// (401, or a 429/5xx outage) falls back to EU. Only report "invalid" when
	// both regions definitively return 401 — if either errored, stay unknown.
	ValidateExpr: `let us = http.get("https://us.posthog.com/api/users/@me/", {
    "Authorization": "Bearer " + finding["secret"]
  }); us.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"region": "us", "email": (us.json?.email ?? ""), "organization": (us.json?.organization?.name ?? "")}
  } : (let eu = http.get("https://eu.posthog.com/api/users/@me/", {
    "Authorization": "Bearer " + finding["secret"]
  }); eu.status in [200, 403] ? {
    "result": "valid",
    "metadata": {"region": "eu", "email": (eu.json?.email ?? ""), "organization": (eu.json?.organization?.name ?? "")}
  } : (us.status == 401 && eu.status == 401) ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(eu))`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `posthogToken = "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZz"`, "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZz"),
		rulebuilder.Match("bare secret", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHC", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHC"),
		rulebuilder.Match("bare secret 2", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH9"),
		rulebuilder.Match("bare secret 3", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lIT", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lIT"),
		rulebuilder.Match("bare secret 4", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ", "phx_WE6v05tg7Z5jXlNPAK_XEPcHzfjsqrpsQE_BdrxHCH92lITZ"),
		rulebuilder.NoMatch("too short", "phx_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"),
		rulebuilder.NoMatch("too long", "phx_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl1"),
		rulebuilder.NoMatch("Wrong prefix", "phy_FNKCx83Ko0JQMuZH1zz94xgK798TCUybkf79ZKYKwKQWbEw"),
	},
})
