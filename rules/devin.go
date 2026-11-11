package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:           "devin-personal-api-key",
	Confidence:   "high",
	Description:  "Detected a Cognition Devin personal API key, which may expose Devin sessions and user data.",
	Regex:        Token(`apk_user_[A-Za-z0-9+/]{120,180}={0,2}`),
	Keywords:     []string{"apk_user_"},
	ValidateExpr: BearerGetValidationExpr("https://api.devin.ai/v1/sessions?limit=1", `(r.body contains "\"sessions\"")`),
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("bare secret", "apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6MjUwZjRhNzc2ZDEyNGVlMTk0NDk5OGNhNmRmNjBiY2I=", "apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6MjUwZjRhNzc2ZDEyNGVlMTk0NDk5OGNhNmRmNjBiY2I="),
		Match("true positive 1", "DEVIN_API_KEY=apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6YTYzNWU0MTA3M2VkNDU3OGFmZDFhMjAxZDhkMjNkODg=", "apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6YTYzNWU0MTA3M2VkNDU3OGFmZDFhMjAxZDhkMjNkODg="),
	},
})

var _ = Add(config.Rule{
	ID:           "devin-service-api-key",
	Confidence:   "high",
	Description:  "Detected a Cognition Devin service API key, which may expose Devin sessions and organization access.",
	Regex:        Token(`apk_[A-Za-z0-9+/]{80,100}={0,2}`),
	Keywords:     []string{"apk_"},
	ValidateExpr: BearerGetValidationExpr("https://api.devin.ai/v1/sessions?limit=1", `(r.body contains "\"sessions\"")`),
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("bare secret", "apk_b3JnLWZhODc5ZTM3Y2FkZjRiNmJiZjJhN2FmMzE4MWRlYzEzOjM0MTU3ZWU4NTZiMjRkMjI5MDYwNzAxOGJmMGEyYzU0", "apk_b3JnLWZhODc5ZTM3Y2FkZjRiNmJiZjJhN2FmMzE4MWRlYzEzOjM0MTU3ZWU4NTZiMjRkMjI5MDYwNzAxOGJmMGEyYzU0"),
		Match("true positive 1", "DEVIN_API_KEY=apk_b3JnLWZhODc5ZTM3Y2FkZjRiNmJiZjJhN2FmMzE4MWRlYzEzOmFjMWE2YWEwZjhjYzQ0OGNiY2Q5ZDJlOTI5MGEyN2Jh", "apk_b3JnLWZhODc5ZTM3Y2FkZjRiNmJiZjJhN2FmMzE4MWRlYzEzOmFjMWE2YWEwZjhjYzQ0OGNiY2Q5ZDJlOTI5MGEyN2Jh"),
		NoMatch("false positive 1", "apk_user_dXNlci0yMDc5ZjllYTUyZDA0OWE0OTVlOWUwNDc2OTJiNWZhYl9vcmctZmE4NzllMzdjYWRmNGI2YmJmMmE3YWYzMTgxZGVjMTM6MjUwZjRhNzc2ZDEyNGVlMTk0NDk5OGNhNmRmNjBiY2I="),
	},
})

var _ = Add(config.Rule{
	ID:           "devin-service-user-token",
	Confidence:   "high",
	Description:  "Detected a Cognition Devin service user token, which may expose Devin service user access.",
	Regex:        Token(`cog_[a-z2-7]{52}`),
	Keywords:     []string{"cog_"},
	ValidateExpr: BearerGetValidationExpr("https://api.devin.ai/v3/self", `(r.body contains "\"principal_type\"") || (r.body contains "\"service_user_id\"")`),
	FilterExpr:   MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("bare secret", "cog_l5osrifmypvazi4j3yko52gj6jfj7qprsmy4lrcf27jas4szffha", "cog_l5osrifmypvazi4j3yko52gj6jfj7qprsmy4lrcf27jas4szffha"),
		Match("true positive 1", "DEVIN_API_KEY=cog_uv23fh6fc5kpaxdqif7hyvmzslnbmwriqita7cqkbb4rpaixnleq", "cog_uv23fh6fc5kpaxdqif7hyvmzslnbmwriqita7cqkbb4rpaixnleq"),
	},
})
